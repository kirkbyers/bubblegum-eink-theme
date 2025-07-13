# Elixir Script (.exs) Sample File for Theme Testing
# This file demonstrates Elixir scripting features and Mix tasks

# Mix.install for dependencies (Elixir 1.12+)
Mix.install([
  {:jason, "~> 1.4"},
  {:httpoison, "~> 2.0"},
  {:csv, "~> 3.0"}
])

# Script modules and functions
defmodule UserDataProcessor do
  @moduledoc """
  A sample data processing script for user management.
  Demonstrates file I/O, HTTP requests, CSV processing, and data transformation.
  """

  require Logger

  # Constants
  @api_base_url "https://jsonplaceholder.typicode.com"
  @output_dir "./output"
  @csv_headers ["id", "name", "username", "email", "phone", "website", "company"]

  def run do
    IO.puts("🚀 Starting User Data Processing Script")

    with :ok <- ensure_output_directory(),
         {:ok, users} <- fetch_users_from_api(),
         :ok <- process_and_save_data(users),
         :ok <- generate_reports(users) do
      IO.puts("✅ Script completed successfully!")
    else
      {:error, reason} ->
        IO.puts("❌ Script failed: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp ensure_output_directory do
    case File.mkdir_p(@output_dir) do
      :ok -> 
        IO.puts("📁 Output directory ready: #{@output_dir}")
        :ok
      {:error, reason} -> 
        {:error, "Failed to create output directory: #{reason}"}
    end
  end

  defp fetch_users_from_api do
    IO.puts("🌐 Fetching users from API...")
    
    case HTTPoison.get("#{@api_base_url}/users") do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, users} ->
            IO.puts("✅ Fetched #{length(users)} users")
            {:ok, users}
          {:error, reason} ->
            {:error, "JSON decode error: #{reason}"}
        end
      
      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "HTTP error: #{status_code}"}
      
      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, "Request failed: #{reason}"}
    end
  end

  defp process_and_save_data(users) do
    IO.puts("📊 Processing user data...")
    
    with {:ok, csv_data} <- convert_to_csv(users),
         {:ok, json_data} <- convert_to_json(users),
         :ok <- save_csv_file(csv_data),
         :ok <- save_json_file(json_data) do
      IO.puts("💾 Data saved successfully")
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp convert_to_csv(users) do
    csv_rows = 
      users
      |> Enum.map(&extract_user_fields/1)
      |> then(&[@csv_headers | &1])
    
    case CSV.encode(csv_rows) |> Enum.to_list() do
      [] -> {:error, "Failed to generate CSV"}
      csv_content -> {:ok, Enum.join(csv_content, "")}
    end
  end

  defp extract_user_fields(user) do
    [
      to_string(user["id"]),
      user["name"] || "",
      user["username"] || "",
      user["email"] || "",
      user["phone"] || "",
      user["website"] || "",
      get_in(user, ["company", "name"]) || ""
    ]
  end

  defp convert_to_json(users) do
    processed_users = 
      users
      |> Enum.map(&process_user_data/1)
      |> Enum.sort_by(& &1.name)

    case Jason.encode(processed_users, pretty: true) do
      {:ok, json} -> {:ok, json}
      {:error, reason} -> {:error, "JSON encode error: #{reason}"}
    end
  end

  defp process_user_data(user) do
    %{
      id: user["id"],
      name: user["name"],
      username: user["username"],
      email: user["email"],
      contact: %{
        phone: user["phone"],
        website: user["website"]
      },
      address: process_address(user["address"]),
      company: get_in(user, ["company", "name"]),
      processed_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp process_address(nil), do: nil
  defp process_address(address) do
    %{
      street: "#{address["street"]} #{address["suite"]}",
      city: address["city"],
      zipcode: address["zipcode"],
      coordinates: %{
        lat: String.to_float(address["geo"]["lat"]),
        lng: String.to_float(address["geo"]["lng"])
      }
    }
  end

  defp save_csv_file(csv_data) do
    file_path = Path.join(@output_dir, "users.csv")
    
    case File.write(file_path, csv_data) do
      :ok -> 
        IO.puts("📄 CSV file saved: #{file_path}")
        :ok
      {:error, reason} -> 
        {:error, "Failed to save CSV: #{reason}"}
    end
  end

  defp save_json_file(json_data) do
    file_path = Path.join(@output_dir, "users.json")
    
    case File.write(file_path, json_data) do
      :ok -> 
        IO.puts("📄 JSON file saved: #{file_path}")
        :ok
      {:error, reason} -> 
        {:error, "Failed to save JSON: #{reason}"}
    end
  end

  defp generate_reports(users) do
    IO.puts("📈 Generating reports...")
    
    reports = [
      {"Domain Distribution", generate_domain_report(users)},
      {"City Distribution", generate_city_report(users)},
      {"Company Statistics", generate_company_report(users)}
    ]

    Enum.each(reports, fn {title, data} ->
      IO.puts("\n#{title}:")
      print_report_data(data)
    end)

    save_reports_file(reports)
  end

  defp generate_domain_report(users) do
    users
    |> Enum.map(fn user ->
      user["email"]
      |> String.split("@")
      |> List.last()
    end)
    |> Enum.frequencies()
    |> Enum.sort_by(&elem(&1, 1), :desc)
  end

  defp generate_city_report(users) do
    users
    |> Enum.map(&get_in(&1, ["address", "city"]))
    |> Enum.reject(&is_nil/1)
    |> Enum.frequencies()
    |> Enum.sort_by(&elem(&1, 1), :desc)
  end

  defp generate_company_report(users) do
    companies = 
      users
      |> Enum.map(&get_in(&1, ["company", "name"]))
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()

    %{
      total_companies: map_size(companies),
      average_employees_per_company: Float.round(length(users) / map_size(companies), 2),
      companies: companies |> Enum.sort_by(&elem(&1, 1), :desc)
    }
  end

  defp print_report_data(data) when is_list(data) do
    data
    |> Enum.take(5)
    |> Enum.each(fn {key, value} ->
      IO.puts("  #{key}: #{value}")
    end)
  end

  defp print_report_data(%{} = data) do
    Enum.each(data, fn
      {:companies, companies} ->
        IO.puts("  Top companies:")
        companies
        |> Enum.take(3)
        |> Enum.each(fn {company, count} ->
          IO.puts("    #{company}: #{count}")
        end)
      
      {key, value} ->
        IO.puts("  #{key}: #{value}")
    end)
  end

  defp save_reports_file(reports) do
    report_content = 
      reports
      |> Enum.map(fn {title, data} ->
        "#{title}:\n#{format_report_data(data)}\n"
      end)
      |> Enum.join("\n")

    file_path = Path.join(@output_dir, "reports.txt")
    
    case File.write(file_path, report_content) do
      :ok -> 
        IO.puts("📊 Reports saved: #{file_path}")
        :ok
      {:error, reason} -> 
        {:error, "Failed to save reports: #{reason}"}
    end
  end

  defp format_report_data(data) when is_list(data) do
    data
    |> Enum.map(fn {key, value} -> "  #{key}: #{value}" end)
    |> Enum.join("\n")
  end

  defp format_report_data(%{companies: companies} = data) do
    main_stats = 
      data
      |> Map.drop([:companies])
      |> Enum.map(fn {key, value} -> "  #{key}: #{value}" end)
      |> Enum.join("\n")

    company_stats = 
      companies
      |> Enum.map(fn {company, count} -> "    #{company}: #{count}" end)
      |> Enum.join("\n")

    main_stats <> "\n  companies:\n" <> company_stats
  end
end

# Task runner for batch processing
defmodule TaskRunner do
  @moduledoc "Utility module for running concurrent tasks"

  def run_parallel_tasks(tasks, timeout \\ 10_000) do
    IO.puts("🔄 Running #{length(tasks)} tasks in parallel...")
    
    start_time = System.monotonic_time(:millisecond)
    
    results = 
      tasks
      |> Enum.map(&Task.async/1)
      |> Enum.map(&Task.await(&1, timeout))
    
    end_time = System.monotonic_time(:millisecond)
    duration = end_time - start_time
    
    IO.puts("⏱️  All tasks completed in #{duration}ms")
    results
  end

  def benchmark_function(fun, iterations \\ 1000) do
    IO.puts("🔬 Benchmarking function with #{iterations} iterations...")
    
    times = 
      for _ <- 1..iterations do
        start_time = System.monotonic_time(:microsecond)
        fun.()
        end_time = System.monotonic_time(:microsecond)
        end_time - start_time
      end

    avg_time = Enum.sum(times) / length(times)
    min_time = Enum.min(times)
    max_time = Enum.max(times)

    IO.puts("📊 Benchmark results:")
    IO.puts("  Average: #{Float.round(avg_time, 2)}μs")
    IO.puts("  Min: #{min_time}μs")
    IO.puts("  Max: #{max_time}μs")

    %{average: avg_time, min: min_time, max: max_time}
  end
end

# Configuration and environment handling
defmodule Config do
  @config_file "config.json"

  def load_config do
    case File.read(@config_file) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, config} -> config
          {:error, _} -> default_config()
        end
      
      {:error, _} ->
        IO.puts("⚠️  Config file not found, using defaults")
        default_config()
    end
  end

  defp default_config do
    %{
      "api_timeout" => 5000,
      "max_retries" => 3,
      "output_format" => "json",
      "debug" => false
    }
  end

  def get_env(key, default \\ nil) do
    System.get_env(key) || default
  end
end

# File utilities with pattern matching
defmodule FileUtils do
  def process_file(file_path) do
    case File.stat(file_path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size > 0 ->
        read_and_process_file(file_path)
      
      {:ok, %File.Stat{type: :regular, size: 0}} ->
        {:error, :empty_file}
      
      {:ok, %File.Stat{type: type}} ->
        {:error, {:invalid_type, type}}
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_and_process_file(file_path) do
    file_path
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.filter(&(&1 != ""))
    |> Stream.with_index(1)
    |> Enum.map(fn {line, line_num} ->
      %{line: line, line_number: line_num, length: String.length(line)}
    end)
  end

  def ensure_directory(path) do
    case File.mkdir_p(path) do
      :ok -> :ok
      {:error, :eexist} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def cleanup_old_files(directory, days_old) do
    cutoff_time = 
      DateTime.utc_now()
      |> DateTime.add(-days_old, :day)
      |> DateTime.to_unix()

    case File.ls(directory) do
      {:ok, files} ->
        old_files = 
          files
          |> Enum.map(&Path.join(directory, &1))
          |> Enum.filter(fn file_path ->
            case File.stat(file_path) do
              {:ok, %File.Stat{mtime: mtime}} ->
                file_time = mtime |> NaiveDateTime.from_erl!() |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix()
                file_time < cutoff_time
              
              {:error, _} -> false
            end
          end)

        Enum.each(old_files, &File.rm/1)
        {:ok, length(old_files)}
      
      {:error, reason} ->
        {:error, reason}
    end
  end
end

# CLI argument parsing
defmodule CLI do
  def parse_args(args) do
    {options, arguments, _invalid} = 
      OptionParser.parse(args, 
        strict: [
          help: :boolean,
          verbose: :boolean,
          output: :string,
          format: :string,
          config: :string
        ],
        aliases: [
          h: :help,
          v: :verbose,
          o: :output,
          f: :format,
          c: :config
        ]
      )

    %{
      options: Map.new(options),
      arguments: arguments
    }
  end

  def print_help do
    IO.puts("""
    User Data Processor

    Usage: elixir sample.exs [options] [arguments]

    Options:
      -h, --help          Show this help message
      -v, --verbose       Enable verbose output
      -o, --output DIR    Output directory (default: ./output)
      -f, --format FORMAT Output format: json, csv, both (default: both)
      -c, --config FILE   Configuration file path

    Examples:
      elixir sample.exs
      elixir sample.exs --verbose --output /tmp/data
      elixir sample.exs --format json --config custom.json
    """)
  end
end

# Main execution logic
defmodule Main do
  def run(args \\ System.argv()) do
    %{options: options, arguments: _arguments} = CLI.parse_args(args)

    cond do
      options[:help] ->
        CLI.print_help()
      
      true ->
        config = Config.load_config()
        
        if options[:verbose] do
          IO.puts("🔧 Configuration: #{inspect(config)}")
          IO.puts("⚙️  Options: #{inspect(options)}")
        end

        # Run the main data processing
        UserDataProcessor.run()

        # Run some benchmarks if verbose
        if options[:verbose] do
          TaskRunner.benchmark_function(fn ->
            1..1000 |> Enum.map(&(&1 * 2)) |> Enum.sum()
          end, 100)
        end
    end
  end
end

# Script execution
case System.argv() do
  ["--help"] -> CLI.print_help()
  ["--test"] -> 
    IO.puts("🧪 Running in test mode...")
    # Could run tests here
  
  args -> Main.run(args)
end