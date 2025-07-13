# Elixir Sample File for Theme Testing
# This file demonstrates various Elixir syntax and constructs for comprehensive theme testing

defmodule UserManager do
  @moduledoc """
  A sample module for managing users with various Elixir language features.
  This module demonstrates GenServer, pattern matching, guards, and more.
  """

  use GenServer
  require Logger
  alias __MODULE__.{User, UserStore}

  # Module attributes
  @default_timeout 5_000
  @max_users 1000
  @valid_roles [:admin, :user, :guest]

  # Type specifications
  @type user_id :: pos_integer()
  @type user_role :: :admin | :user | :guest
  @type user_status :: :active | :inactive | :pending

  @type user :: %{
          id: user_id(),
          name: String.t(),
          email: String.t(),
          role: user_role(),
          status: user_status(),
          created_at: DateTime.t(),
          preferences: map() | nil
        }

  @type state :: %{
          users: %{user_id() => user()},
          user_count: non_neg_integer(),
          max_users: pos_integer()
        }

  # Struct definition
  defmodule User do
    @moduledoc "User struct with validation"

    @enforce_keys [:id, :name, :email, :role]
    defstruct [
      :id,
      :name,
      :email,
      :role,
      status: :pending,
      created_at: nil,
      preferences: %{}
    ]

    @type t :: %__MODULE__{
            id: pos_integer(),
            name: String.t(),
            email: String.t(),
            role: atom(),
            status: atom(),
            created_at: DateTime.t() | nil,
            preferences: map()
          }

    # Protocol implementation
    defimpl String.Chars do
      def to_string(%User{name: name, email: email, role: role}) do
        "#{name} <#{email}> (#{role})"
      end
    end
  end

  # Behavior implementation (Exception)
  defmodule UserError do
    defexception [:message, :reason, :user_id]

    @type t :: %__MODULE__{
            message: String.t(),
            reason: atom(),
            user_id: pos_integer() | nil
          }

    def exception(opts) when is_list(opts) do
      reason = Keyword.get(opts, :reason, :unknown)
      user_id = Keyword.get(opts, :user_id)
      message = Keyword.get(opts, :message, format_message(reason, user_id))

      %__MODULE__{message: message, reason: reason, user_id: user_id}
    end

    defp format_message(:not_found, user_id), do: "User with ID #{user_id} not found"
    defp format_message(:invalid_email, _), do: "Invalid email format"
    defp format_message(:max_users_reached, _), do: "Maximum number of users reached"
    defp format_message(reason, _), do: "User error: #{reason}"
  end

  # GenServer callbacks
  @impl GenServer
  def init(opts \\ []) do
    max_users = Keyword.get(opts, :max_users, @max_users)

    state = %{
      users: %{},
      user_count: 0,
      max_users: max_users
    }

    Logger.info("UserManager started with max_users: #{max_users}")
    {:ok, state}
  end

  @impl GenServer
  def handle_call({:create_user, user_attrs}, _from, state) do
    case create_user_impl(user_attrs, state) do
      {:ok, user, new_state} ->
        Logger.info("Created user: #{user.name}")
        {:reply, {:ok, user}, new_state}

      {:error, reason} ->
        Logger.warning("Failed to create user: #{reason}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:get_user, user_id}, _from, state) when is_integer(user_id) and user_id > 0 do
    case Map.get(state.users, user_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      user ->
        {:reply, {:ok, user}, state}
    end
  end

  @impl GenServer
  def handle_call({:update_user, user_id, updates}, _from, state) do
    case update_user_impl(user_id, updates, state) do
      {:ok, user, new_state} ->
        {:reply, {:ok, user}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:delete_user, user_id}, _from, state) do
    case Map.pop(state.users, user_id) do
      {nil, _users} ->
        {:reply, {:error, :not_found}, state}

      {user, users} ->
        new_state = %{state | users: users, user_count: state.user_count - 1}
        Logger.info("Deleted user: #{user.name}")
        {:reply, {:ok, user}, new_state}
    end
  end

  @impl GenServer
  def handle_call(:list_users, _from, state) do
    users = state.users |> Map.values() |> Enum.sort_by(& &1.created_at, DateTime)
    {:reply, {:ok, users}, state}
  end

  @impl GenServer
  def handle_call({:filter_users, filter_fn}, _from, state) when is_function(filter_fn, 1) do
    filtered_users =
      state.users
      |> Map.values()
      |> Enum.filter(filter_fn)
      |> Enum.sort_by(& &1.name)

    {:reply, {:ok, filtered_users}, state}
  end

  @impl GenServer
  def handle_cast({:broadcast_user_event, event, user}, state) do
    Phoenix.PubSub.broadcast(MyApp.PubSub, "users", {event, user})
    {:noreply, state}
  end

  @impl GenServer
  def handle_info({:cleanup_inactive_users, days}, state) do
    cutoff_date = DateTime.utc_now() |> DateTime.add(-days, :day)

    {inactive_users, active_users} =
      Enum.split_with(state.users, fn {_id, user} ->
        user.status == :inactive and DateTime.compare(user.created_at, cutoff_date) == :lt
      end)

    Logger.info("Cleaned up #{length(inactive_users)} inactive users")

    new_state = %{
      state
      | users: Map.new(active_users),
        user_count: length(active_users)
    }

    {:noreply, new_state}
  end

  @impl GenServer
  def handle_info(msg, state) do
    Logger.warning("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # Public API
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def create_user(attrs, timeout \\ @default_timeout) do
    GenServer.call(__MODULE__, {:create_user, attrs}, timeout)
  end

  def get_user(user_id, timeout \\ @default_timeout) when is_integer(user_id) do
    GenServer.call(__MODULE__, {:get_user, user_id}, timeout)
  end

  def update_user(user_id, updates, timeout \\ @default_timeout) do
    GenServer.call(__MODULE__, {:update_user, user_id, updates}, timeout)
  end

  def delete_user(user_id, timeout \\ @default_timeout) do
    GenServer.call(__MODULE__, {:delete_user, user_id}, timeout)
  end

  def list_users(timeout \\ @default_timeout) do
    GenServer.call(__MODULE__, :list_users, timeout)
  end

  def filter_users(filter_fn, timeout \\ @default_timeout) when is_function(filter_fn, 1) do
    GenServer.call(__MODULE__, {:filter_users, filter_fn}, timeout)
  end

  def get_users_by_role(role, timeout \\ @default_timeout) when role in @valid_roles do
    filter_users(&(&1.role == role), timeout)
  end

  def get_active_users(timeout \\ @default_timeout) do
    filter_users(&(&1.status == :active), timeout)
  end

  # Private helper functions with pattern matching and guards
  defp create_user_impl(attrs, state) when state.user_count >= state.max_users do
    {:error, :max_users_reached}
  end

  defp create_user_impl(attrs, state) when is_map(attrs) do
    with {:ok, validated_attrs} <- validate_user_attrs(attrs),
         {:ok, user} <- build_user(validated_attrs, state) do
      new_users = Map.put(state.users, user.id, user)
      new_state = %{state | users: new_users, user_count: state.user_count + 1}
      {:ok, user, new_state}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_user_impl(_attrs, _state), do: {:error, :invalid_attrs}

  defp update_user_impl(user_id, updates, state) when is_map(updates) do
    case Map.get(state.users, user_id) do
      nil ->
        {:error, :not_found}

      user ->
        with {:ok, validated_updates} <- validate_user_updates(updates),
             updated_user <- struct(user, validated_updates) do
          new_users = Map.put(state.users, user_id, updated_user)
          new_state = %{state | users: new_users}
          {:ok, updated_user, new_state}
        else
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp build_user(attrs, _state) do
    user = %User{
      id: generate_user_id(),
      name: attrs.name,
      email: attrs.email,
      role: attrs.role,
      status: Map.get(attrs, :status, :pending),
      created_at: DateTime.utc_now(),
      preferences: Map.get(attrs, :preferences, %{})
    }

    {:ok, user}
  end

  # Pattern matching with guards
  defp validate_user_attrs(%{name: name, email: email, role: role} = attrs)
       when is_binary(name) and is_binary(email) and role in @valid_roles do
    case validate_email(email) do
      true -> {:ok, attrs}
      false -> {:error, :invalid_email}
    end
  end

  defp validate_user_attrs(_attrs), do: {:error, :missing_required_fields}

  defp validate_user_updates(updates) when is_map(updates) do
    updates
    |> Enum.reduce_while({:ok, %{}}, fn
      {:name, name}, {:ok, acc} when is_binary(name) ->
        {:cont, {:ok, Map.put(acc, :name, name)}}

      {:email, email}, {:ok, acc} when is_binary(email) ->
        case validate_email(email) do
          true -> {:cont, {:ok, Map.put(acc, :email, email)}}
          false -> {:halt, {:error, :invalid_email}}
        end

      {:role, role}, {:ok, acc} when role in @valid_roles ->
        {:cont, {:ok, Map.put(acc, :role, role)}}

      {:status, status}, {:ok, acc} when status in [:active, :inactive, :pending] ->
        {:cont, {:ok, Map.put(acc, :status, status)}}

      {:preferences, prefs}, {:ok, acc} when is_map(prefs) ->
        {:cont, {:ok, Map.put(acc, :preferences, prefs)}}

      {key, _value}, _acc ->
        {:halt, {:error, {:invalid_field, key}}}
    end)
  end

  # Regular expressions
  defp validate_email(email) when is_binary(email) do
    email_regex = ~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/
    Regex.match?(email_regex, email)
  end

  defp validate_email(_), do: false

  # Unique ID generation using various techniques
  defp generate_user_id do
    :erlang.system_time(:microsecond)
  end

  # Using case, cond, and if statements
  def get_user_display_name(%User{name: name, email: email}) do
    case String.trim(name) do
      "" ->
        email |> String.split("@") |> hd() |> String.capitalize()

      trimmed_name ->
        cond do
          String.length(trimmed_name) > 50 -> String.slice(trimmed_name, 0, 47) <> "..."
          String.length(trimmed_name) < 2 -> email
          true -> trimmed_name
        end
    end
  end

  def get_user_permissions(%User{role: role, status: status}) do
    base_permissions = get_base_permissions(role)

    if status == :active do
      base_permissions
    else
      [:read_only]
    end
  end

  # Multiple function clauses with pattern matching
  defp get_base_permissions(:admin), do: [:read, :write, :delete, :admin]
  defp get_base_permissions(:user), do: [:read, :write]
  defp get_base_permissions(:guest), do: [:read]
  defp get_base_permissions(_), do: []

  # Working with processes and tasks
  def async_user_report(user_ids) when is_list(user_ids) do
    user_ids
    |> Enum.map(&Task.async(fn -> get_user(&1) end))
    |> Enum.map(&Task.await/1)
    |> Enum.filter(&match?({:ok, _}, &1))
    |> Enum.map(&elem(&1, 1))
  end

  # Using for comprehensions
  def filter_and_transform_users(filter_opts \\ %{}) do
    for {:ok, users} <- [list_users()],
        user <- users,
        matches_filter?(user, filter_opts),
        into: %{} do
      {user.id, transform_user_for_api(user)}
    end
  end

  defp matches_filter?(user, opts) do
    Enum.all?(opts, fn
      {:role, role} -> user.role == role
      {:status, status} -> user.status == status
      {:name_contains, text} -> String.contains?(String.downcase(user.name), String.downcase(text))
      _ -> true
    end)
  end

  defp transform_user_for_api(%User{} = user) do
    %{
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status,
      display_name: get_user_display_name(user),
      permissions: get_user_permissions(user),
      created_at: DateTime.to_iso8601(user.created_at)
    }
  end

  # Using Stream for lazy evaluation
  def stream_user_emails do
    {:ok, users} = list_users()

    users
    |> Stream.filter(&(&1.status == :active))
    |> Stream.map(& &1.email)
    |> Stream.uniq()
    |> Enum.to_list()
  end

  # Recursive functions
  def calculate_user_hierarchy(user_id, depth \\ 0, max_depth \\ 5)
  def calculate_user_hierarchy(_user_id, depth, max_depth) when depth >= max_depth, do: []

  def calculate_user_hierarchy(user_id, depth, max_depth) do
    case get_user(user_id) do
      {:ok, user} ->
        children = get_user_children(user_id)

        [user | Enum.flat_map(children, &calculate_user_hierarchy(&1, depth + 1, max_depth))]

      {:error, _} ->
        []
    end
  end

  defp get_user_children(_user_id) do
    # Mock implementation - would normally query database
    []
  end

  # Working with binaries and bitstrings
  def encode_user_id(user_id) when is_integer(user_id) do
    <<user_id::big-integer-size(64)>>
  end

  def decode_user_id(<<user_id::big-integer-size(64)>>) do
    {:ok, user_id}
  end

  def decode_user_id(_), do: {:error, :invalid_format}

  # Using try/rescue for error handling
  def safe_create_user(attrs) do
    try do
      create_user(attrs)
    rescue
      error in UserError ->
        Logger.error("UserError: #{error.message}")
        {:error, error.reason}

      error ->
        Logger.error("Unexpected error: #{inspect(error)}")
        {:error, :unexpected_error}
    end
  end

  # Using with for error handling
  def create_and_activate_user(attrs) do
    with {:ok, user} <- create_user(attrs),
         {:ok, activated_user} <- update_user(user.id, %{status: :active}),
         :ok <- broadcast_user_created(activated_user) do
      {:ok, activated_user}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, {:unexpected, error}}
    end
  end

  defp broadcast_user_created(user) do
    GenServer.cast(__MODULE__, {:broadcast_user_event, :user_created, user})
    :ok
  end

  # Macros (simplified example)
  defmacro defuser(name, attrs) do
    quote do
      def unquote(:"create_#{name}")() do
        create_user(unquote(attrs))
      end
    end
  end

  # Using the macro
  defuser(:admin, %{name: "Admin User", email: "admin@example.com", role: :admin})
  defuser(:guest, %{name: "Guest User", email: "guest@example.com", role: :guest})
end

# Module using behaviours
defmodule UserManager.UserStore do
  @moduledoc "Behaviour for user storage backends"

  @callback get_user(user_id :: pos_integer()) :: {:ok, map()} | {:error, atom()}
  @callback save_user(user :: map()) :: {:ok, map()} | {:error, atom()}
  @callback delete_user(user_id :: pos_integer()) :: :ok | {:error, atom()}
  @callback list_users() :: {:ok, [map()]} | {:error, atom()}
end

# Implementation of the behaviour
defmodule UserManager.InMemoryStore do
  @behaviour UserManager.UserStore

  @impl true
  def get_user(user_id) do
    # Implementation details
    {:ok, %{id: user_id, name: "Test User"}}
  end

  @impl true
  def save_user(user) do
    # Implementation details
    {:ok, user}
  end

  @impl true
  def delete_user(_user_id) do
    :ok
  end

  @impl true
  def list_users do
    {:ok, []}
  end
end

# Protocol definition
defprotocol UserManager.Serializable do
  @doc "Converts a data structure to a serializable format"
  def serialize(data)
end

# Protocol implementations
defimpl UserManager.Serializable, for: UserManager.User do
  def serialize(%UserManager.User{} = user) do
    %{
      id: user.id,
      name: user.name,
      email: user.email,
      role: Atom.to_string(user.role),
      status: Atom.to_string(user.status),
      created_at: DateTime.to_iso8601(user.created_at),
      preferences: user.preferences
    }
  end
end

defimpl UserManager.Serializable, for: List do
  def serialize(list) when is_list(list) do
    Enum.map(list, &UserManager.Serializable.serialize/1)
  end
end

# Agent for simple state management
defmodule UserManager.StatsAgent do
  use Agent

  def start_link(initial_value \\ %{}) do
    Agent.start_link(fn -> initial_value end, name: __MODULE__)
  end

  def increment_counter(key) do
    Agent.update(__MODULE__, fn state ->
      Map.update(state, key, 1, &(&1 + 1))
    end)
  end

  def get_counter(key) do
    Agent.get(__MODULE__, fn state ->
      Map.get(state, key, 0)
    end)
  end

  def get_all_stats do
    Agent.get(__MODULE__, & &1)
  end
end