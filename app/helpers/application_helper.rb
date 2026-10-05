module ApplicationHelper
  def short_host_id(external_id)
    external_id.to_s.first(12)
  end

  def boolean_value_label(boolean, key = "current", enabled: "Enabled", disabled: "Disabled")
    return "Unavailable" if boolean["status"] == "unavailable"
    return "Unknown" unless boolean["status"] == "observed" && boolean[key].in?([true, false])

    boolean[key] ? enabled : disabled
  end

  def boolean_reported_default(boolean)
    boolean.key?("default") ? boolean["default"] : boolean["persistent"]
  end

  def boolean_reported_default_label(boolean)
    boolean_value_label(boolean.merge("default" => boolean_reported_default(boolean)), "default", enabled: "On", disabled: "Off")
  end

  def boolean_observed_label(boolean)
    label = boolean_value_label(boolean, "current", enabled: "On", disabled: "Off")
    return label unless boolean["status"] == "observed" && boolean["current"].in?([true, false]) && boolean["default"].in?([true, false]) && boolean["current"] != boolean["default"]

    "#{label} (host default #{boolean["default"] ? "On" : "Off"})"
  end

  def port_provenance_label(value)
    case value
    when "custom" then "Local customization"
    when "not_confirmed_custom" then "Not in local port list"
    when "unknown" then "Local list not observed"
    else "Not recorded"
    end
  end
end
