export default function SubmitBtn(props) {
  return (
    <button
      type="submit"
      data-twe-ripple-init
      data-twe-ripple-color="light"
      className="inline-block w-full rounded-full bg-neutral-800 px-6 pb-2 pt-2.5 text-lg font-medium uppercase leading-normal text-neutral-50 shadow-dark-3 transition duration-150 ease-in-out motion-reduce:transition-none dark:shadow-black/30 dark:hover:shadow-dark-strong dark:focus:shadow-dark-strong dark:active:shadow-dark-strong"
    >
      {props.children}
    </button>
  );
}
