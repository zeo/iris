//! data quotas: an allowance of bytes per local day, week, or month, for one
//! app or the whole machine. the quota list lives in a json file beside the
//! rules, like the caps. an app that spends its quota is blocked by timed rules
//! that lapse when the period starts over; the machine-wide quota only warns.

use iris_core::{AppId, Granularity, Quota, QuotaLimit, QuotaPeriod};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DAY_MS: i64 = 86_400_000;

fn quotas_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("quotas.json")
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    app: Option<AppId>,
    limit: QuotaLimit,
    /// the period start of the last warning, and the percentage it reported
    #[serde(default)]
    fired: Option<(u64, u8)>,
    /// rule ids this quota put in force, lifted when the quota changes
    #[serde(default)]
    blocks: Vec<i64>,
    #[serde(skip)]
    counted: Counted,
}

/// bytes of the whole minutes from `period` up to `through`, so each check
/// only reads the minutes it has not counted yet
#[derive(Clone, Copy, Default)]
struct Counted {
    period: u64,
    through: u64,
    bytes: u64,
    used: u64,
}

/// a quota that just crossed a threshold this period
pub struct Reached {
    pub app: Option<AppId>,
    pub limit: QuotaLimit,
    pub used: u64,
    pub percent: u8,
    pub until_ms: u64,
}

#[derive(Default)]
pub struct QuotaBook {
    entries: Vec<Entry>,
}

impl QuotaBook {
    pub fn open() -> QuotaBook {
        let entries = std::fs::read_to_string(quotas_path())
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        QuotaBook { entries }
    }

    pub fn list(&self, now_ms: u64) -> Vec<Quota> {
        self.entries
            .iter()
            .map(|entry| {
                let (start, end) = period_bounds(now_ms, &entry.limit, utc_offset_ms);
                Quota {
                    app: entry.app.clone(),
                    limit: entry.limit,
                    used: if entry.counted.period == start { entry.counted.used } else { 0 },
                    period_start_ms: start,
                    period_end_ms: end,
                }
            })
            .collect()
    }

    /// set or clear one quota; returns the rule ids its old self put in force
    pub fn set(&mut self, app: Option<AppId>, limit: Option<QuotaLimit>) -> anyhow::Result<Vec<i64>> {
        if let Some(limit) = &limit {
            anyhow::ensure!(limit.bytes > 0, "a quota must be above zero; block the app instead");
            anyhow::ensure!((1..=28).contains(&limit.reset_day), "the reset day must be from 1 to 28");
        }
        let lifted = self
            .entries
            .iter()
            .filter(|entry| entry.app == app)
            .flat_map(|entry| entry.blocks.clone())
            .collect();
        self.entries.retain(|entry| entry.app != app);
        if let Some(limit) = limit {
            self.entries.push(Entry { app, limit, fired: None, blocks: Vec::new(), counted: Counted::default() });
        }
        self.save()?;
        Ok(lifted)
    }

    /// remember the rules that now block an app for its spent quota
    pub fn record_blocks(&mut self, app: &AppId, ids: Vec<i64>) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.app.as_ref() == Some(app)) {
            entry.blocks = ids;
        }
        if let Err(error) = self.save() {
            tracing::warn!("could not save the quota list: {error}");
        }
    }

    /// count what each quota has used and return the ones that crossed a
    /// threshold since the last check. `usage` sums an app's bytes, or every
    /// app's, over `[from, to)`
    pub fn check(
        &mut self,
        now_ms: u64,
        offset: impl Fn(i64) -> i64,
        usage: impl Fn(Option<&AppId>, u64, u64) -> u64,
    ) -> Vec<Reached> {
        let minute = Granularity::Minute.bucket_start(now_ms);
        let mut reached = Vec::new();
        let mut changed = false;
        for entry in &mut self.entries {
            let (start, end) = period_bounds(now_ms, &entry.limit, &offset);
            let counted = &mut entry.counted;
            if counted.period != start || counted.through > minute {
                *counted = Counted { period: start, through: start, ..Counted::default() };
            }
            if counted.through < minute {
                counted.bytes += usage(entry.app.as_ref(), counted.through, minute);
                counted.through = minute;
            }
            counted.used = counted.bytes + usage(entry.app.as_ref(), minute, u64::MAX);
            if entry.fired.is_some_and(|(period, _)| period != start) {
                entry.fired = None;
                entry.blocks.clear();
                changed = true;
            }
            let thresholds: &[u8] = if entry.app.is_some() { &[100] } else { &[100, 80] };
            let percent = counted.used.saturating_mul(100) / entry.limit.bytes.max(1);
            let already = entry.fired.map_or(0, |(_, percent)| percent);
            if let Some(&crossed) = thresholds.iter().find(|threshold| percent >= u64::from(**threshold)) {
                if crossed > already {
                    entry.fired = Some((start, crossed));
                    changed = true;
                    reached.push(Reached {
                        app: entry.app.clone(),
                        limit: entry.limit,
                        used: counted.used,
                        percent: crossed,
                        until_ms: end,
                    });
                }
            }
        }
        if changed {
            if let Err(error) = self.save() {
                tracing::warn!("could not save the quota list: {error}");
            }
        }
        reached
    }

    fn save(&self) -> anyhow::Result<()> {
        crate::rules::write_atomic(&quotas_path(), &serde_json::to_vec_pretty(&self.entries)?)
    }
}

impl Reached {
    pub fn message(&self) -> String {
        let (used, limit) = (amount(self.used), amount(self.limit.bytes));
        match &self.app {
            Some(app) => {
                let (period, until) = match self.limit.period {
                    QuotaPeriod::Day => ("daily", "midnight".to_string()),
                    QuotaPeriod::Week => ("weekly", "Monday".to_string()),
                    QuotaPeriod::Month => ("monthly", format!("the {}", ordinal(self.limit.reset_day))),
                };
                format!("{} used its {limit} {period} quota and is blocked until {until}", app.file_name())
            }
            None if self.percent >= 100 => format!("Data plan used up: {used} of {limit} this period"),
            None => format!("Data plan {}% used: {used} of {limit} this period", self.percent),
        }
    }
}

/// data plans are quoted decimally, so this matches the meter in the UI
fn amount(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1e9)
    } else {
        format!("{:.0} MB", bytes as f64 / 1e6)
    }
}

fn ordinal(day: u8) -> String {
    let suffix = match (day % 10, day % 100) {
        (1, 11) | (2, 12) | (3, 13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{day}{suffix}")
}

/// the utc instants where the period holding `now_ms` starts and ends, with
/// `offset` giving local time minus utc at an instant
fn period_bounds(now_ms: u64, limit: &QuotaLimit, offset: impl Fn(i64) -> i64) -> (u64, u64) {
    let now = now_ms as i64;
    let today = (now + offset(now)).div_euclid(DAY_MS);
    let (start, end) = match limit.period {
        QuotaPeriod::Day => (today, today + 1),
        QuotaPeriod::Week => {
            // day 0 was a thursday
            let monday = today - (today + 3).rem_euclid(7);
            (monday, monday + 7)
        }
        QuotaPeriod::Month => {
            let reset = u32::from(limit.reset_day.clamp(1, 28));
            let (year, month, day) = civil_from_days(today);
            let (year, month) = match (day >= reset, month) {
                (true, _) => (year, month),
                (false, 1) => (year - 1, 12),
                (false, _) => (year, month - 1),
            };
            let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
            (days_from_civil(year, month, reset), days_from_civil(next_year, next_month, reset))
        }
    };
    let midnight = |day: i64| {
        let local = day * DAY_MS;
        (local - offset(local - offset(local))).max(0) as u64
    };
    (midnight(start), midnight(end))
}

// days since 1970-01-01 to and from a proleptic gregorian date, after
// howard hinnant's chrono-compatible algorithms
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * i64::from((month + 9) % 12) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// local time minus utc at an instant, in the machine's time zone
#[cfg(windows)]
pub fn utc_offset_ms(at_ms: i64) -> i64 {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::Time::SystemTimeToTzSpecificLocalTime;
    let (year, month, day) = civil_from_days(at_ms.div_euclid(DAY_MS));
    let rest = at_ms.rem_euclid(DAY_MS);
    let utc = SYSTEMTIME {
        wYear: year as u16,
        wMonth: month as u16,
        wDayOfWeek: 0,
        wDay: day as u16,
        wHour: (rest / 3_600_000) as u16,
        wMinute: (rest / 60_000 % 60) as u16,
        wSecond: (rest / 1000 % 60) as u16,
        wMilliseconds: (rest % 1000) as u16,
    };
    let mut local = SYSTEMTIME::default();
    // safety: both pointers name live stack values for the duration of the call
    if unsafe { SystemTimeToTzSpecificLocalTime(None, &utc, &mut local) }.is_err() {
        return 0;
    }
    let local_ms = days_from_civil(i64::from(local.wYear), u32::from(local.wMonth), u32::from(local.wDay)) * DAY_MS
        + i64::from(local.wHour) * 3_600_000
        + i64::from(local.wMinute) * 60_000
        + i64::from(local.wSecond) * 1000
        + i64::from(local.wMilliseconds);
    local_ms - at_ms
}

#[cfg(target_os = "linux")]
pub fn utc_offset_ms(at_ms: i64) -> i64 {
    let seconds = at_ms.div_euclid(1000) as libc::time_t;
    // safety: localtime_r fills the zeroed tm and keeps no reference to either
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff as i64 * 1000
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn utc_offset_ms(_at_ms: i64) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3_600_000;

    fn at(year: i64, month: u32, day: u32, hour: i64) -> u64 {
        (days_from_civil(year, month, day) * DAY_MS + hour * HOUR) as u64
    }

    fn limit(period: QuotaPeriod, reset_day: u8) -> QuotaLimit {
        QuotaLimit { period, bytes: 1000, reset_day }
    }

    #[test]
    fn civil_dates_round_trip_across_leap_years() {
        for days in [-1, 0, 11_016, 19_782, 20_403, 47_482] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(days_from_civil(2028, 2, 29)), (2028, 2, 29));
    }

    #[test]
    fn periods_start_at_local_midnight_monday_and_the_reset_day() {
        let utc = |_| 0;
        // 2026-11-11 is a wednesday
        let now = at(2026, 11, 11, 15);
        assert_eq!(period_bounds(now, &limit(QuotaPeriod::Day, 1), utc), (at(2026, 11, 11, 0), at(2026, 11, 12, 0)));
        assert_eq!(period_bounds(now, &limit(QuotaPeriod::Week, 1), utc), (at(2026, 11, 9, 0), at(2026, 11, 16, 0)));
        assert_eq!(period_bounds(now, &limit(QuotaPeriod::Month, 15), utc), (at(2026, 10, 15, 0), at(2026, 11, 15, 0)));
        assert_eq!(period_bounds(at(2027, 1, 3, 0), &limit(QuotaPeriod::Month, 5), utc), (at(2026, 12, 5, 0), at(2027, 1, 5, 0)));
        assert_eq!(period_bounds(at(2026, 12, 20, 0), &limit(QuotaPeriod::Month, 5), utc), (at(2026, 12, 5, 0), at(2027, 1, 5, 0)));
    }

    #[test]
    fn a_zone_ahead_of_utc_starts_the_day_before_utc_midnight() {
        let tokyo = |_| 9 * HOUR;
        // 20:00 utc on the 11th is already 05:00 on the 12th in tokyo
        let (start, end) = period_bounds(at(2026, 11, 11, 20), &limit(QuotaPeriod::Day, 1), tokyo);
        assert_eq!((start, end), (at(2026, 11, 11, 15), at(2026, 11, 12, 15)));
    }

    #[test]
    fn an_app_quota_fires_once_per_period_and_the_machine_warns_at_80_then_100() {
        let app = AppId::from_path("c:/games/game.exe");
        let mut book = QuotaBook {
            entries: vec![
                Entry { app: Some(app.clone()), limit: limit(QuotaPeriod::Day, 1), fired: None, blocks: vec![], counted: Counted::default() },
                Entry { app: None, limit: limit(QuotaPeriod::Day, 1), fired: None, blocks: vec![], counted: Counted::default() },
            ],
        };
        let used = std::cell::Cell::new(0u64);
        let usage = |_: Option<&AppId>, from: u64, _to: u64| if from == at(2026, 11, 11, 0) { used.get() } else { 0 };
        let check = |book: &mut QuotaBook, now| {
            book.entries.iter_mut().for_each(|entry| entry.counted = Counted::default());
            book.check(now, |_| 0, usage).into_iter().map(|r| (r.app.is_some(), r.percent)).collect::<Vec<_>>()
        };
        let noon = at(2026, 11, 11, 12);
        used.set(850);
        assert_eq!(check(&mut book, noon), vec![(false, 80)]);
        assert_eq!(check(&mut book, noon), vec![]);
        used.set(1000);
        assert_eq!(check(&mut book, noon), vec![(true, 100), (false, 100)]);
        assert_eq!(check(&mut book, noon), vec![]);
        used.set(0);
        book.entries[0].blocks = vec![7];
        assert_eq!(check(&mut book, at(2026, 11, 12, 1)), vec![]);
        assert!(book.entries[0].fired.is_none() && book.entries[0].blocks.is_empty());
    }

    #[test]
    fn the_local_offset_is_whole_quarter_hours_within_a_day() {
        let offset = utc_offset_ms(days_from_civil(2026, 7, 1) * DAY_MS);
        assert_eq!(offset % (15 * 60_000), 0);
        assert!(offset.abs() <= 14 * HOUR);
    }

    #[test]
    fn messages_name_the_app_the_limit_and_when_it_lifts() {
        let reached = Reached {
            app: Some(AppId::from_path("c:/games/game.exe")),
            limit: QuotaLimit { period: QuotaPeriod::Month, bytes: 5_000_000_000, reset_day: 2 },
            used: 5_100_000_000,
            percent: 100,
            until_ms: 0,
        };
        assert_eq!(reached.message(), "game.exe used its 5.0 GB monthly quota and is blocked until the 2nd");
        let plan = Reached { app: None, percent: 80, used: 400_000_000_000, limit: QuotaLimit { bytes: 500_000_000_000, ..reached.limit }, ..reached };
        assert_eq!(plan.message(), "Data plan 80% used: 400.0 GB of 500.0 GB this period");
        assert_eq!(ordinal(11), "11th");
        assert_eq!(ordinal(22), "22nd");
    }
}
