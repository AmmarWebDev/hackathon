export default function InputField(props) {
  props = { type: "text", placeholder: "...", ...props };
  return (
    <div className="input-wrapper" data-placeholder={props.placeholder}>
      <input
        type={props.type}
        name={props.name}
        autoComplete={props.autoComplete}
      />
    </div>
  );
}
