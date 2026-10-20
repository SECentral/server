class Api::V1::IssueResolutionsController < Api::V1::BaseController
  rescue_from ResolutionWorkflow::EvidenceChanged do |error|
    render json: { error: { code: "evidence_changed", message: error.message } }, status: :conflict
  end

  def show
    render json: workflow.call
  end

  def update
    review = params.permit(home_content_review: [:path, :confirmed])[:home_content_review]&.to_h
    render json: workflow.select!(params.require(:candidate_id), params.require(:evidence_version), home_content_review: review)
  end

  def destroy
    render json: workflow.clear!
  end

  private

  def workflow
    ResolutionWorkflow.new(current_organization.issues.find(params[:id]), operator: session[:operator_username])
  end
end
