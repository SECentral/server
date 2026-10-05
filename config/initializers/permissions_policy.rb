# Emits the current "Permissions-Policy" header. Rails' built-in
# ActionDispatch::PermissionsPolicy middleware still writes the obsolete
# "Feature-Policy" header, so SECentral defines this minimal middleware and
# builds the policy value with the standard ActionDispatch::PermissionsPolicy
# builder instead.
class PermissionsPolicyHeader
  HEADER = "Permissions-Policy"

  def initialize(app, value)
    @app = app
    @value = value
  end

  def call(env)
    status, headers, body = @app.call(env)
    headers[HEADER] = @value unless headers[HEADER]
    [status, headers, body]
  end
end

# SECentral uses none of the browser features below (no camera, microphone,
# geolocation, payment, USB, fullscreen, etc.), so every one is disabled.
policy = ActionDispatch::PermissionsPolicy.new do |policy|
  policy.accelerometer :none
  policy.autoplay :none
  policy.camera :none
  policy.display_capture :none
  policy.encrypted_media :none
  policy.fullscreen :none
  policy.geolocation :none
  policy.gyroscope :none
  policy.microphone :none
  policy.payment :none
  policy.picture_in_picture :none
  policy.usb :none
end

Rails.application.config.middleware.use PermissionsPolicyHeader, policy.build
