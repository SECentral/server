class FileContextMatcher
  def self.call(path, mappings)
    new(path, mappings).call
  end

  def initialize(path, mappings)
    @path = path
    @mappings = Array(mappings)
  end

  def call
    matches = []
    invalid_patterns = []
    @mappings.each do |mapping|
      pattern = mapping["pattern"].to_s
      begin
        matches << mapping if Regexp.new("\\A(?:#{pattern})\\z").match?(@path.to_s)
      rescue RegexpError
        invalid_patterns << pattern
      end
    end
    { path: @path, matches: matches, invalid_patterns: invalid_patterns.uniq }
  end
end
