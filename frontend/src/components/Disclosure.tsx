import { ExpandableSection, type ExpandableSectionProps } from "@patternfly/react-core";
import AngleRightIcon from "@patternfly/react-icons/dist/esm/icons/angle-right-icon";
import { useState } from "react";

export function Disclosure({ className = "", ...props }: Omit<ExpandableSectionProps, "ref">) {
  const [expanded, setExpanded] = useState(false);
  return <ExpandableSection {...props} isExpanded={props.isExpanded ?? expanded} onToggle={(event, open) => {
    if (props.isExpanded === undefined) setExpanded(open);
    props.onToggle?.(event, open);
  }} className={`issue-disclosure ${className}`} toggleIcon={<AngleRightIcon aria-hidden="true" />} />;
}
