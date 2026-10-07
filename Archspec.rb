source "app/**/*.rb", "lib/**/*.{rb,rake}"

component :controllers, in: "app/controllers/**/*.rb"
component :models, in: "app/models/**/*.rb"
component :services, in: "app/services/**/*.rb"
component :queries, in: "app/queries/**/*.rb"
component :jobs, in: "app/jobs/**/*.rb"

[models, services, queries, jobs].each do |component|
  component.cannot_use :controllers, because: "HTTP handling belongs in controllers"
  component.cannot_call :render, :redirect_to, :params, :session, :cookies
end

# Name-based checks catch obvious writes, not indirect side effects or raw SQL.
queries.cannot_call :save, :save!, :create, :create!, :update, :update!,
  :update_all, :update_columns, :update_column, :delete, :delete_all, :delete_by,
  :destroy, :destroy!, :destroy_all, :destroy_by, :touch, :toggle, :toggle!,
  :increment, :increment!, :decrement, :decrement!, :insert, :insert!,
  :insert_all, :upsert, :upsert_all
