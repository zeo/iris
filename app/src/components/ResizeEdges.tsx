import { getCurrentWindow } from "@tauri-apps/api/window";

type ResizeDirection =
  | "East"
  | "North"
  | "NorthEast"
  | "NorthWest"
  | "South"
  | "SouthEast"
  | "SouthWest"
  | "West";

const directions: ResizeDirection[] = [
  "North",
  "NorthEast",
  "East",
  "SouthEast",
  "South",
  "SouthWest",
  "West",
  "NorthWest",
];

export function ResizeEdges() {
  return (
    <>
      {directions.map((direction) => (
        <div
          class={`resize-edge ${direction.toLowerCase()}`}
          onMouseDown={(event) => {
            if (event.button === 0) void getCurrentWindow().startResizeDragging(direction);
          }}
        />
      ))}
    </>
  );
}
