import { Label, type LabelProps } from "@patternfly/react-core";
import { CheckCircleIcon, ExclamationTriangleIcon, TimesCircleIcon } from "@patternfly/react-icons";

export function StatusLabel({ color, ...props }: LabelProps) {
  const icon = color === "green" ? <CheckCircleIcon aria-hidden="true" />
    : color === "red" ? <TimesCircleIcon aria-hidden="true" /> : <ExclamationTriangleIcon aria-hidden="true" />;
  return <Label {...props} color={color} icon={icon} />;
}
