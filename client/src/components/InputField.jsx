export default function InputField(props) {
  props = { type: "text", placeholder: "Please fill this field", ...props };
  return (
    <div className="input-wrapper mb-10" data-placeholder={props.placeholder}>
      <input
        {...props}
        placeholder=""
        className="w-full"
      />
    </div>
  );
}
