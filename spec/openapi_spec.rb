require "rails_helper"
require "yaml"

RSpec.describe "OpenAPI document" do
  HTTP_METHODS = %w[get put post delete options head patch trace].freeze

  def openapi
    @openapi ||= YAML.load_file(Rails.root.join("openapi", "openapi.yaml"))
  end

  def route_template(route)
    route.path.spec.to_s
          .sub(/\(.:format\)\z/, "")
          .sub(/\(\.\{format\}\)\z/, "")
          .gsub(/:([a-zA-Z_][a-zA-Z0-9_]*)/) { "{#{$1}}" }
  end

  def resolve_ref(node)
    if node.is_a?(Hash) && node.keys == ["$ref"] && node["$ref"].to_s.start_with?("#/")
      node["$ref"].delete_prefix("#/").split("/").reduce(openapi) do |target, key|
        target.fetch(key.to_s)
      end
    else
      node
    end
  end

  def each_ref(node, &block)
    case node
    when Hash
      if node.keys == ["$ref"]
        yield node["$ref"]
      else
        node.each_value { |value| each_ref(value, &block) }
      end
    when Array
      node.each { |item| each_ref(item, &block) }
    end
  end

  def operations
    openapi.fetch("paths").flat_map do |path, item|
      HTTP_METHODS.filter_map do |method|
        operation = item[method]
        [path, method, operation] if operation
      end
    end
  end

  it "is well-formed with the expected metadata" do
    expect(openapi["openapi"]).to match(/\A3\./)
    expect(openapi["info"]["title"]).to be_present
    expect(openapi["info"]["version"]).to be_present
    expect(openapi["paths"]).to be_a(Hash)
    expect(openapi.dig("components", "securitySchemes")).to be_present
  end

  it "documents every operator API route" do
    documented = openapi.fetch("paths").keys
    operator_api_paths = Rails.application.routes.routes.filter_map do |route|
      next unless route.defaults[:controller].to_s.start_with?("api/v1/")

      route_template(route)
    end.uniq

    expect(operator_api_paths).to all(be_present)
    expect(documented).to include(*operator_api_paths)
  end

  it "resolves every internal $ref" do
    refs = []
    each_ref(openapi) { |ref| refs << ref }
    expect(refs).to all(be_present)

    errors = refs.filter_map do |ref|
      next unless ref.start_with?("#/")

      begin
        resolve_ref({ "$ref" => ref })
        nil
      rescue KeyError
        "unresolvable #{ref}"
      end
    end

    expect(errors).to be_empty
  end

  it "defines a complete operation for every endpoint" do
    expect(operations).to be_present

    operations.each do |path, method, operation|
      expect(operation["operationId"]).to be_present, "#{method.upcase} #{path} needs an operationId"
      expect(operation["summary"]).to be_present, "#{method.upcase} #{path} needs a summary"
      responses = operation["responses"]
      expect(responses).to be_a(Hash), "#{method.upcase} #{path} needs responses"
      success = responses.keys.any? { |code| code.to_s.match?(/\A2\d\d\z/) }
      expect(success).to be(true), "#{method.upcase} #{path} needs a success response"
    end

    operation_ids = operations.map { |path, _method, operation| operation["operationId"] }
    expect(operation_ids.uniq.size).to eq(operation_ids.size), "operationIds must be unique"
  end

  it "documents atomic ingestion and an explicit pre-persistence error distinct from other 422 failures" do
    operation = openapi.dig("paths", "/api/v1/events", "post")
    expect(operation["security"]).to eq([{ "ingestionBearer" => [] }])
    expect(operation.dig("responses", "202", "description")).to include("never partial acceptance")
    schema = openapi.dig("components", "schemas", "PrePersistenceEventValidationError", "properties", "error")
    expect(schema["required"]).to include("phase", "details")
    expect(schema.dig("properties", "phase", "const")).to eq("pre_persistence")
    details = schema.dig("properties", "details")
    expect(details["minItems"]).to eq(1)
    pattern = Regexp.new(details.dig("items", "properties", "path", "pattern"))
    expect("events[1].records[5].payload").to match(pattern)
    expect("host_id").not_to match(pattern)
    expect(operation.dig("responses", "422", "content", "application/json", "schema", "oneOf").size).to eq(2)
  end
end
