// App.jsx
import "./App.css";
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  useCallback,
} from "react";
import { Ripple, initTWE, Input } from "tw-elements";

// Components
import InputField from "./components/InputField";
import SubmitBtn from "./components/SubmitBtn";

export default function App() {
  useEffect(() => {
    initTWE({ Ripple, Input });
  }, []);

  const [isRegister, setIsRegister] = useState(false);

  // Refs to the inner content (we'll measure these)
  const loginContentRef = useRef(null);
  const registerContentRef = useRef(null);

  // wrapper height in px
  const [height, setHeight] = useState(0);

  // Measure the active content's height (uses offsetHeight -> includes padding/borders)
  const measureHeight = useCallback(() => {
    const activeEl = isRegister
      ? registerContentRef.current
      : loginContentRef.current;
    if (activeEl) {
      setHeight(activeEl.offsetHeight);
    }
  }, [isRegister]);

  // Measure on mount and when active form changes. Use rAF + timeout to be robust with layout/fonts.
  useLayoutEffect(() => {
    measureHeight();
    const rafId = requestAnimationFrame(measureHeight);
    const t = setTimeout(measureHeight, 50);
    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(t);
    };
  }, [measureHeight]);

  // Window resize -> re-measure
  useEffect(() => {
    window.addEventListener("resize", measureHeight);
    return () => window.removeEventListener("resize", measureHeight);
  }, [measureHeight]);

  // Observe content changes (validation messages, async content, etc.)
  useEffect(() => {
    // Guard for environments without ResizeObserver
    if (typeof ResizeObserver === "undefined") return;

    const ro = new ResizeObserver(() => {
      // Always measure whichever form is active (keeps height in sync)
      measureHeight();
    });
    if (loginContentRef.current) ro.observe(loginContentRef.current);
    if (registerContentRef.current) ro.observe(registerContentRef.current);

    return () => ro.disconnect();
  }, [measureHeight]);

  return (
    <div className="container m-auto px-4 pt-[80px]">
      <section className="w-full m-auto border !border-neutral-500 max-w-xl rounded-2xl">
        {/* Header / tab buttons */}
        <header className="form-header">
          <div
            className="inline-flex w-full"
            role="tablist"
            aria-label="Auth forms"
          >
            <button
              type="button"
              role="tab"
              aria-pressed={!isRegister}
              onClick={() => setIsRegister(false)}
              className={`inline-block flex-1 relative overflow-hidden rounded-xl px-6 pb-[6px] pt-2 text-lg font-medium uppercase leading-normal transition duration-150 ease-in-out
                ${
                  !isRegister
                    ? "border-b-2 !border-r-2 !border-black bg-white text-neutral-900"
                    : "border-b border-transparent text-neutral-500"
                }
              `}
              data-twe-ripple-init
              data-twe-ripple-color="dark"
            >
              Login
            </button>

            <button
              type="button"
              role="tab"
              aria-pressed={isRegister}
              onClick={() => setIsRegister(true)}
              className={`inline-block flex-1 relative overflow-hidden rounded-xl px-6 pb-[6px] pt-2 text-lg font-medium uppercase leading-normal transition duration-150 ease-in-out
                ${
                  isRegister
                    ? "border-b-2 !border-r-2 !border-black bg-white text-neutral-900"
                    : "border-b border-transparent text-neutral-500"
                }
              `}
              data-twe-ripple-init
              data-twe-ripple-color="info"
            >
              Register
            </button>
          </div>
        </header>

        {/* Card body */}
        {/* keep overflow-hidden here to hide the off-screen form during horizontal slide */}
        <div className="card-body relative overflow-hidden px-0">
          {/* This wrapper gets a controlled height (px). Animate height only. */}
          <div
            className="relative transition-[height] duration-300 ease-in-out"
            style={{ height: `${height}px` }}
          >
            {/* Login form (outer form kept absolute to allow sliding) */}
            <form
              id="login"
              className={`absolute inset-0 duration-300 ease-in-out
                ${
                  isRegister
                    ? "-translate-x-full opacity-0 pointer-events-none"
                    : "translate-x-0 opacity-100"
                }
              `}
              aria-hidden={isRegister}
            >
              {/* measure this inner box */}
              <div ref={loginContentRef} className="p-10">
                <InputField
                  type="text"
                  name="username"
                  autoComplete="username"
                  placeholder="Username"
                />
                <InputField
                  type="password"
                  name="password"
                  autoComplete="current-password"
                  placeholder="Password"
                />
                <button
                  type="button"
                  className="block text-right pb-[5px] ms-auto text-sm text-neutral-500"
                >
                  Forgot Password?
                </button>
                <SubmitBtn>Sign in</SubmitBtn>
              </div>
            </form>

            {/* Register form */}
            <form
              id="register"
              className={`absolute inset-0 duration-300 ease-in-out
                ${
                  isRegister
                    ? "translate-x-0 opacity-100"
                    : "translate-x-full opacity-0 pointer-events-none"
                }
              `}
              aria-hidden={!isRegister}
            >
              {/* measure this inner box */}
              <div ref={registerContentRef} className="p-10">
                <InputField
                  type="text"
                  name="reg-username"
                  autoComplete="username"
                  placeholder="Username"
                />
                <InputField
                  type="email"
                  name="reg-email"
                  autoComplete="email"
                  placeholder="Email Address"
                />
                <InputField
                  type="password"
                  name="reg-password"
                  autoComplete="new-password"
                  placeholder="Password"
                />
                <InputField
                  type="password"
                  name="reg-confirm"
                  autoComplete="new-password"
                  placeholder="Confirm Password"
                />
                <SubmitBtn>Register</SubmitBtn>
              </div>
            </form>
          </div>
        </div>
      </section>
    </div>
  );
}
