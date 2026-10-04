import { createRoot } from "react-dom/client";
import "./styles.css";
import { Router } from "./router.jsx";
import App from "./App.jsx";

createRoot(document.getElementById("root")).render(
  <Router>
    <App />
  </Router>
);
