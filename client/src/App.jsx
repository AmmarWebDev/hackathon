import "./App.css";
import { useEffect } from "react";
import { Ripple, initTWE, Input } from "tw-elements";
import InputField from "./components/InputField";

export default function App() {
  useEffect(() => {
    initTWE({ Ripple, Input });
  }, []);

  return (
    <section id="forms">
      <form id="register">
        <InputField
          name="name"
          autoComplete="name"
          placeholder="Enter your name"
        />
      </form>
      <form id="login"></form>
    </section>
  );
}
