class SpaController < ActionController::Base
  class << self
    def index_file
      Rails.public_path.join("spa", "index.html")
    end
  end

  def index
    unless File.exist?(self.class.index_file)
      return render plain: "The SPA build is missing. Build it with `npm run build` in server/frontend.", status: :service_unavailable
    end

    response.headers["Cache-Control"] = "no-store"
    render file: self.class.index_file, content_type: "text/html"
  end
end
