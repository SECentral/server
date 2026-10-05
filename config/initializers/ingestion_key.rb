if Rails.env.production? && ENV["SECENTRAL_INGESTION_KEY"].blank?
  raise "SECENTRAL_INGESTION_KEY is required in production"
end
