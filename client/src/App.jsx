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

  const loginContentRef = useRef(null);
  const registerContentRef = useRef(null);

  const [height, setHeight] = useState(0);

  const measureHeight = useCallback(() => {
    const activeEl = isRegister
      ? registerContentRef.current
      : loginContentRef.current;
    if (activeEl) {
      setHeight(activeEl.offsetHeight);
    }
  }, [isRegister]);

  useLayoutEffect(() => {
    measureHeight();
    const rafId = requestAnimationFrame(measureHeight);
    const t = setTimeout(measureHeight, 50);
    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(t);
    };
  }, [measureHeight]);

  useEffect(() => {
    window.addEventListener("resize", measureHeight);
    return () => window.removeEventListener("resize", measureHeight);
  }, [measureHeight]);

  useEffect(() => {
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      measureHeight();
    });
    if (loginContentRef.current) ro.observe(loginContentRef.current);
    if (registerContentRef.current) ro.observe(registerContentRef.current);
    return () => ro.disconnect();
  }, [measureHeight]);

  return (
    <div className="container px-4 pt-[80px]">
      <section className="w-full m-auto border max-w-xl rounded-2xl">
        {/* Header / tab buttons */}
        <header className="form-header">
          {/* changed inline-flex -> flex so buttons distribute well */}
          <div className="flex w-full" role="tablist" aria-label="Auth forms">
            <button
              type="button"
              role="tab"
              aria-pressed={!isRegister}
              onClick={() => setIsRegister(false)}
              data-twe-ripple-init
              data-twe-ripple-color="dark"
              className={`flex-1 w-full relative overflow-hidden rounded-xl px-6 pb-[6px] pt-2 text-lg font-medium uppercase leading-normal transition duration-150 ease-in-out box-border
                border-b-[3px] border-r-[3px]
                ${
                  !isRegister
                    ? "!border-black !border-r-2 !border-b-2 bg-white text-neutral-900"
                    : "border-transparent text-neutral-500"
                }`}
            >
              Login
            </button>

            <button
              type="button"
              role="tab"
              aria-pressed={isRegister}
              onClick={() => setIsRegister(true)}
              data-twe-ripple-init
              data-twe-ripple-color="dark"
              className={`flex-1 w-full relative overflow-hidden rounded-xl px-6 pb-[6px] pt-2 text-lg font-medium uppercase leading-normal transition duration-150 ease-in-out box-border
                border-b-[3px] border-r-[3px]
                ${
                  isRegister
                    ? "!border-black !border-r-2 !border-b-2 bg-white text-neutral-900"
                    : "border-transparent text-neutral-500"
                }`}
            >
              Register
            </button>
          </div>
        </header>

        {/* Card body */}
        <div className="card-body relative overflow-hidden px-0">
          <div
            className="relative transition-[height] duration-300 ease-in-out"
            style={{ height: `${height}px` }}
          >
            {/* Login form */}
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
                  className="block text-right pb-[5px] ms-auto text-sm text-neutral-500 hover:text-black"
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
