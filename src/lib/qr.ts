import * as fs from "fs";
import jsQR from "jsqr";
import * as jpeg from "jpeg-js";
import { PNG } from "pngjs";

export async function decodeQrImage(filePath: string): Promise<string | null> {
  const buffer = fs.readFileSync(filePath);
  const pixels = decodePixels(buffer);
  if (!pixels) return null;
  const result = jsQR(pixels.data, pixels.width, pixels.height);
  return result ? result.data : null;
}

function decodePixels(buffer: Buffer): { data: Uint8ClampedArray; width: number; height: number } | null {
  try {
    const png = PNG.sync.read(buffer);
    return { data: new Uint8ClampedArray(png.data), width: png.width, height: png.height };
  } catch {
    // Not a PNG, try JPEG below.
  }
  try {
    const decoded = jpeg.decode(buffer, { useTArray: true });
    return { data: new Uint8ClampedArray(decoded.data), width: decoded.width, height: decoded.height };
  } catch {
    return null;
  }
}
