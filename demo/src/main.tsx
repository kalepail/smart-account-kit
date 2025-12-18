import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

// Polyfill Buffer for browser (required by stellar-sdk)
import { Buffer } from "buffer";
globalThis.Buffer = Buffer;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
