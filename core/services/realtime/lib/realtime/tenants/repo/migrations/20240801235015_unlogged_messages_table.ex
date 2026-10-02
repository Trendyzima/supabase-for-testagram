defmodule Realtime.Tenants.Migrations.UnloggedMessagesTable do
  @moduledoc false
  use Ecto.Migration

  def change do
    execute """
    -- Commented to have oriole compatibility
    -- ALTER TABLE realtime.messages SET UNLOGGED;
    """
  end
end
