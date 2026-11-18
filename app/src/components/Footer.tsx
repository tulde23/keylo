import type { AppInfo } from "../api";

/** The bar along the bottom of the window: which Keylo build this is, and its store. */
export default function Footer({ info }: { info: AppInfo }) {
  return (
    <footer className="footer">
      <span className="footer-build" title={`${info.storeName} · ${info.dataDir}`}>Keylo {info.version}</span>
    </footer>
  );
}
