class Api::V1::PolicyDraftsController < Api::V1::BaseController
  rescue_from ArgumentError, ActiveRecord::RecordInvalid do |error|
    render json: { error: { code: "invalid_value", message: error.message } }, status: :unprocessable_content
  end

  def index
    issue = Issue.find(params.require(:issue_id))
    render json: { drafts: PolicyDraft.where(organization: issue.organization).order(updated_at: :desc).limit(50).map { |d| PolicyDraftWorkspace.serialize(d) } }
  end

  def create
    issue = Issue.find(params.require(:issue_id))
    draft = PolicyDraft.create!(organization: issue.organization, name: params.require(:name), operator: session[:operator_username])
    render json: PolicyDraftWorkspace.serialize(draft), status: :created
  end

  def stage
    issue = Issue.find(params.require(:issue_id))
    draft = PolicyDraft.where(organization: issue.organization).find(params[:id])
    occurrence = issue.occurrences.find(params.require(:occurrence_id))
    PolicyDraftWorkspace.stage!(draft, issue, occurrence)
    render json: PolicyDraftWorkspace.serialize(draft.reload)
  end

  def destroy_entry
    draft = PolicyDraft.find(params[:id])
    draft.with_lock do
      draft.policy_draft_entries.find(params[:entry_id]).destroy!
      draft.update!(status: "draft")
    end
    render json: PolicyDraftWorkspace.serialize(draft)
  end

  def export
    draft = PolicyDraft.find(params[:id])
    render json: PolicyDraftWorkspace.export(draft, format: params.require(:format), module_name: params[:module_name], literal_confirmed: params[:literal_confirmed], evidence_version: params[:evidence_version])
  end
end
