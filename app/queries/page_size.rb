class PageSize
  class Invalid < ArgumentError; end

  def self.parse(value, default: 25, max: 100)
    return default if value.nil?
    unless (value.is_a?(String) || value.is_a?(Integer)) && value.to_s.match?(/\A[1-9]\d{0,2}\z/) && value.to_i <= max
      raise Invalid, "limit must be an integer between 1 and #{max}"
    end
    value.to_i
  end
end
