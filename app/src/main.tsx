import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import Approve from "./components/Approve";
import "./styles.css";

// keylow --approve opens index.html#approve: only the approval card.
const approving = window.location.hash === "#approve";

createRoot(document.getElementById("root")!).render(
  <StrictMode>{approving ? <Approve /> : <App />}</StrictMode>,
);
