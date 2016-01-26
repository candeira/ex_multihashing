defmodule Multihashing.Mixfile do
  use Mix.Project

  def project do
    [app: :multihashing,
     version: "0.0.1",
     elixir: "~> 1.2",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:monad, "~> 1.0.4"},
      {:dialyxir, github: "jeremyjh/dialyxir"},
      {:multihash, github: "zabirauf/ex_multihash", branch: "master"},
      {:inch_ex, only: :docs},
      {:sha3, github: "szktty/erlang-sha3"}
    ]
  end

end
