class PreserveSupersededOccurrences < ActiveRecord::Migration[8.1]
  def change
    add_column :occurrences, :superseded_at, :datetime
  end
end
