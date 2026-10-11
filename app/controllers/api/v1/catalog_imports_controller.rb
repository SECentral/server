class Api::V1::CatalogImportsController < Api::V1::BaseController
  PREVIEW_LIFETIME = 10.minutes
  wrap_parameters false
  # Reject JSON/multipart before Rails/CSRF can parse an unbounded request body.
  prepend_before_action :read_bounded_upload

  rescue_from DistributionCatalogArtifact::Invalid do |error|
    import_error(error.code, error.message, path: error.path, status: error.code == "upload_too_large" ? :content_too_large : :unprocessable_content)
  end
  rescue_from ImportDistributionCatalog::InvalidName do |error|
    import_error("invalid_display_name", error.message, path: "display_name")
  end
  rescue_from ImportDistributionCatalog::Conflict do
    import_error("loaded_policy_conflict", "Another catalog content digest claims this loaded-policy identity", status: :conflict)
  end

  def preview
    return import_error("invalid_upload", "Only optional display_name is accepted") if (request.query_parameters.keys - ["display_name"]).any?

    name = request.query_parameters["display_name"]
    result = ImportDistributionCatalog.preview(artifact: DistributionCatalogArtifact.new(@bytes), display_name: name)
    artifact = result.artifact
    expires_at = PREVIEW_LIFETIME.from_now
    token = nil
    unless result.outcome == "conflict"
      session[:catalog_import_boundary] ||= SecureRandom.hex(32)
      token = verifier.generate({ "bytes_sha256" => Digest::SHA256.hexdigest(@bytes), "display_name" => name, "boundary" => session[:catalog_import_boundary], "operator" => operator_username }, expires_at: expires_at, purpose: "catalog_import")
    end
    render json: { preview: {
      validation_status: "valid", supported: true,
      schema_version: artifact.schema_version,
      collector_semantics_version: artifact.catalog.fetch("collector_semantics_version"),
      content_digest: artifact.content_digest,
      loaded_policy_digest: artifact.catalog.dig("policy", "loaded_policy_digest"),
      platform: artifact.catalog.fetch("platform"), policy_type: artifact.catalog.dig("policy", "type"),
      policy_packages: artifact.catalog.dig("policy", "packages"),
      acquisition: artifact.metadata.slice("collector_version", "collected_at"),
      families: {
        booleans: { status: "complete", count: artifact.catalog.dig("families", "booleans", "entries").size },
        ports: { status: "complete", count: artifact.catalog.dig("families", "ports", "mappings").size, protocols: DistributionCatalogArtifact::PORT_PROTOCOLS }
      },
      display_name: result.display_name, outcome: result.outcome,
      reason: { "create_new_revision" => "A new immutable revision will be created", "reuse_existing_revision" => "Identical content already exists; confirmation appends import evidence only and preserves its name/lifecycle", "conflict" => "Another content digest claims this loaded-policy identity" }.fetch(result.outcome),
      existing_revision: result.revision && { id: result.revision.id, content_digest: result.revision.content_digest, display_name: result.revision.display_name, lifecycle: result.revision.catalog_management.lifecycle },
      preview_token: token, expires_at: token ? expires_at.iso8601 : nil
    } }
  end

  def confirm
    return import_error("invalid_upload", "Confirmation accepts no query parameters") if request.query_parameters.any?

    token = request.headers["X-Catalog-Preview"].to_s
    receipt = verifier.verified(token, purpose: "catalog_import") if token.bytesize <= 2048
    unless receipt && receipt["boundary"] == session[:catalog_import_boundary] && receipt["operator"] == operator_username
      return import_error("invalid_preview", "Preview expired or does not belong to this session; validate again")
    end
    unless ActiveSupport::SecurityUtils.secure_compare(receipt.fetch("bytes_sha256"), Digest::SHA256.hexdigest(@bytes))
      return import_error("preview_bytes_changed", "Uploaded bytes changed after preview; validate again")
    end

    result = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(@bytes), display_name: receipt["display_name"], imported_by: operator_username, source_kind: "operator_upload")
    revision = result.revision
    render json: {
      outcome: result.created ? "create_new_revision" : "reuse_existing_revision",
      catalog: { id: revision.id, content_digest: revision.content_digest, loaded_policy_digest: revision.loaded_policy_digest, display_name: revision.display_name, lifecycle: revision.catalog_management.lifecycle },
      catalog_import: { id: result.catalog_import.id, imported_at: result.catalog_import.created_at, imported_by: result.catalog_import.imported_by, source_kind: result.catalog_import.source_kind, comparison_report: result.catalog_import.comparison_report }
    }, status: result.created ? :created : :ok
  end

  private

  def read_bounded_upload
    return import_error("invalid_upload_media_type", "Send JSON artifact bytes as application/octet-stream", status: :unsupported_media_type) unless request.media_type == "application/octet-stream"
    return import_error("upload_too_large", "Catalog exceeds 2 MiB", status: :content_too_large) if request.content_length.to_i > DistributionCatalogArtifact::MAX_BYTES

    @bytes = request.body.read(DistributionCatalogArtifact::MAX_BYTES + 1).to_s
    return import_error("upload_too_large", "Catalog exceeds 2 MiB", status: :content_too_large) if @bytes.bytesize > DistributionCatalogArtifact::MAX_BYTES
    import_error("empty_upload", "Catalog is empty") if @bytes.empty?
  end

  def verifier
    Rails.application.message_verifier("catalog_import_preview")
  end

  def import_error(code, message, path: nil, status: :unprocessable_content)
    render json: { error: { code: code, message: message, path: path } }, status: status
  end
end
