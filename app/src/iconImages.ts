// Icon images: uploaded, pasted or downloaded pictures used as icons. Each is resized here to fit a
// 128×128 transparent square (aspect ratio kept, centred, never cropped, at most 2× enlarged), as
// the C# app does, then stored by Rust as icons/{hash}.png and named "img" + hash.
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

const CANVAS = 128;

export const isImageIcon = (icon: string | null | undefined): icon is string =>
  !!icon && /^img[0-9a-f]{32}$/i.test(icon);

// ---------------------------------------------------------------------------- display

const cache = new Map<string, Promise<string | null>>();

function load(name: string): Promise<string | null> {
  let p = cache.get(name);
  if (!p) {
    p = invoke<string | null>("icon_image", { name }).catch(() => null);
    cache.set(name, p);
  }
  return p;
}

/** The data: URL of an icon image (null while loading, or if the file is gone). */
export function useIconImage(icon: string | null | undefined): string | null {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setUrl(null);
    if (isImageIcon(icon)) load(icon).then((u) => live && setUrl(u));
    return () => { live = false; };
  }, [icon]);
  return url;
}

// ---------------------------------------------------------------------------- import

function decode(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("That isn't an image Keylo can read."));
    img.src = src;
  });
}

function readAsDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(new Error("Couldn't read that file."));
    reader.readAsDataURL(blob);
  });
}

/** Resizes an image (a data: URL) to the 128×128 icon PNG; returns the PNG as base64. */
async function toIconPng(dataUrl: string): Promise<string> {
  const img = await decode(dataUrl);
  const w = img.naturalWidth || CANVAS, h = img.naturalHeight || CANVAS;
  const scale = Math.min(CANVAS / w, CANVAS / h, 2);
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = CANVAS;
  const ctx = canvas.getContext("2d")!;
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(img, (CANVAS - w * scale) / 2, (CANVAS - h * scale) / 2, w * scale, h * scale);
  return canvas.toDataURL("image/png").split(",")[1];
}

async function store(dataUrl: string): Promise<string> {
  const name = await invoke<string>("save_icon_image", { png: await toIconPng(dataUrl) });
  cache.delete(name);
  return name;
}

/** A picked or pasted file; returns the icon name. */
export async function importImageFile(file: Blob): Promise<string> {
  if (file.type && !file.type.startsWith("image/")) throw new Error("That file isn't an image.");
  if (file.size > 5 * 1024 * 1024) throw new Error("That image is too large (the most is 5 MB).");
  return store(await readAsDataUrl(file));
}

/** An image address (downloaded by Keylo, not the web view); returns the icon name. */
export async function importImageUrl(url: string): Promise<string> {
  const trimmed = url.trim();
  const dataUrl = trimmed.startsWith("data:image/") ? trimmed : await invoke<string>("fetch_image", { url: trimmed });
  return store(dataUrl);
}
