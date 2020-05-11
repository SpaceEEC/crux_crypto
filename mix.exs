defmodule Crux.Crypto.MixProject do
  use Mix.Project

  def project() do
    [
      app: :crux_crypto,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:elixir_make] ++ Mix.compilers(),
      files: [
        "lib",
        "LICENSE",
        "mix.exs",
        "README.md",
        "src/crypto.c",
        "Makefile",
        "Makefile.win"
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application() do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps() do
    [
      # Since using a compiler from the local project is not through through by mix...
      {:elixir_make, "~> 0.4", runtime: false}
    ]
  end
end
