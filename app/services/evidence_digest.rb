class EvidenceDigest
  def self.call(event)
    digest = Digest::SHA256.new
    write_string(digest, event.fetch("completion_reason"))
    write_uint64(digest, event.fetch("records").length)

    event.fetch("records").each do |record|
      write_uint64(digest, record.fetch("position"))
      write_uint64(digest, IngestEvents.type_code(record.fetch("type")))
      write_string(digest, Time.iso8601(record.fetch("timestamp")).utc.iso8601(6))
      write_uint64(digest, record.fetch("sequence"))
      payload = Base64.strict_decode64(record.fetch("payload"))
      write_uint64(digest, payload.bytesize)
      digest << payload
    end

    digest.hexdigest
  end

  def self.write_string(digest, value)
    bytes = value.to_s.b
    write_uint64(digest, bytes.bytesize)
    digest << bytes
  end
  private_class_method :write_string

  def self.write_uint64(digest, value)
    digest << [Integer(value)].pack("Q>")
  end
  private_class_method :write_uint64
end
