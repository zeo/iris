import { JSX } from "solid-js";

// hand-authored stroke icons on a 16x16 grid, currentColor, 1.4 stroke. no icon
// library. each icon is a FUNCTION so every <Icon> call builds fresh path nodes;
// a shared JSX node can only live in one place in the DOM, so reusing one icon in
// two spots would make it vanish from the first.
const paths: Record<string, () => JSX.Element> = {
  shield: () => <path d="M8 1.6 2.6 3.6v4.2c0 3.1 2.2 5.3 5.4 6.6 3.2-1.3 5.4-3.5 5.4-6.6V3.6L8 1.6Z" />,
  activity: () => <path d="M1 8 L4.5 8 L6.4 3 L8.4 13 L10 8 L15 8" />,
  graph: () => (
    <>
      <path d="M1.8 14V2M14.2 14H1.8" />
      <path d="M3 11l3-3 2.4 2 4-5" />
    </>
  ),
  clock: () => (
    <>
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.4V8l2.6 1.6" />
    </>
  ),
  bell: () => <path d="M4 7a4 4 0 0 1 8 0c0 3 1.2 4 1.2 4H2.8S4 10 4 7ZM6.4 13.4a1.7 1.7 0 0 0 3.2 0" />,
  minimize: () => <path d="M2.5 8h11" />,
  maximize: () => <rect x="2.8" y="2.8" width="10.4" height="10.4" rx="1.2" />,
  close: () => <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />,
  eye: () => (
    <>
      <path d="M1 8s2.6-4.6 7-4.6S15 8 15 8s-2.6 4.6-7 4.6S1 8 1 8Z" />
      <circle cx="8" cy="8" r="2.1" />
    </>
  ),
  globe: () => (
    <>
      <circle cx="8" cy="8" r="6.2" />
      <path d="M1.8 8h12.4M8 1.8c1.7 1.8 2.6 3.9 2.6 6.2S9.7 12.4 8 14.2C6.3 12.4 5.4 10.3 5.4 8S6.3 3.6 8 1.8Z" />
    </>
  ),
  search: () => (
    <>
      <circle cx="7" cy="7" r="4.6" />
      <path d="m10.5 10.5 3 3" />
    </>
  ),
  plus: () => <path d="M8 3v10M3 8h10" />,
  chevron: () => <path d="m4 6 4 4 4-4" />,
  sun: () => (
    <>
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1v1.6M8 13.4V15M1 8h1.6M13.4 8H15M3 3l1.1 1.1M11.9 11.9 13 13M13 3l-1.1 1.1M4.1 11.9 3 13" />
    </>
  ),
  moon: () => <path d="M13.4 9.2A5.6 5.6 0 1 1 6.8 2.6 4.4 4.4 0 0 0 13.4 9.2Z" />,
  monitor: () => (
    <>
      <rect x="1.8" y="2.6" width="12.4" height="8.2" rx="1.2" />
      <path d="M5.6 13.4h4.8M8 10.8v2.6" />
    </>
  ),
  block: () => (
    <>
      <circle cx="8" cy="8" r="6.2" />
      <path d="m3.8 3.8 8.4 8.4" />
    </>
  ),
  check: () => <path d="m3 8.4 3.2 3.2L13 4.8" />,
  filter: () => <path d="M2 3h12l-4.6 5.4V13L6.6 11.4V8.4L2 3Z" />,
  x: () => <path d="M4 4l8 8M12 4l-8 8" />,
  cpu: () => (
    <>
      <rect x="4.5" y="4.5" width="7" height="7" rx="1" />
      <path d="M6.5 1.8v2M9.5 1.8v2M6.5 12.2v2M9.5 12.2v2M1.8 6.5h2M1.8 9.5h2M12.2 6.5h2M12.2 9.5h2" />
    </>
  ),
  out: () => <path d="M4 12L12 4M6 4h6v6" />,
  in: () => <path d="M12 4L4 12M10 12H4V6" />,
  power: () => (
    <>
      <path d="M8 1.8v6" />
      <path d="M4.2 4.4a5.2 5.2 0 1 0 7.6 0" />
    </>
  ),
  settings: () => (
    <>
      <circle cx="8" cy="8" r="2.2" />
      <path d="M8 1.4v2M8 12.6v2M1.4 8h2M12.6 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4" />
    </>
  ),
  download: () => (
    <>
      <path d="M8 2v8M4.6 6.8 8 10.2l3.4-3.4" />
      <path d="M2.8 13.4h10.4" />
    </>
  ),
  upload: () => (
    <>
      <path d="M8 10.2V2.2M4.6 5.6 8 2.2l3.4 3.4" />
      <path d="M2.8 13.4h10.4" />
    </>
  ),
  plug: () => (
    <>
      <path d="M5.5 2v3M10.5 2v3" />
      <path d="M4 5h8v2.2a4 4 0 0 1-8 0V5Z" />
      <path d="M8 11.2V14.4" />
    </>
  ),
};

export function Icon(props: { name: keyof typeof paths | string; class?: string; size?: number }) {
  const s = props.size ?? 16;
  const build = () => (paths[props.name] ?? paths.eye)();
  return (
    <svg
      class={props.class}
      width={s}
      height={s}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.4"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {build()}
    </svg>
  );
}
