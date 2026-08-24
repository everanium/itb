# bench_stream — stream-pump throughput vs plaintext size (Streaming
# Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Each iteration runs a
# full incremental session (begin -> write 1 MiB slices, draining the
# spool after each write -> end -> drain until finished -> free).
#
# Env-var overrides identical to bench_message (defaults match the
# root Go BENCH3.md pin):
#
#   ITB_PROFILE        streaming-noaead-triple-v1
#   ITB_INNER_HASH     areion512
#   ITB_KEY_BITS       1024
#   ITB_NONCE_BITS     512
#   ITB_WITH_PARALLAX  false
#   ITB_WITH_WRAPPER   false
#   ITB_BENCH_MIN_SEC  5
#
# Invocation (from bindings/elixir, after ./build.sh):
#   mix run bench/bench_stream.exs

Code.require_file("bench_util.exs", __DIR__)

defmodule BenchStream do
  import Bitwise

  @min_iters 3
  @pump_buf 1 <<< 20

  def main do
    # Bench-scale allocation churn leaks Go scratch heap unboundedly
    # without a soft memory cap + aggressive GC; the return values
    # report the previous settings, not an error.
    _ = ITB.set_memory_limit(512 <<< 20)
    _ = ITB.set_gc_percent(20)

    profile = BenchUtil.env("ITB_PROFILE", "streaming-noaead-triple-v1")
    {:ok, pipe} = ITB.init(profile, BenchUtil.bench_opts())
    BenchUtil.header()

    for size <- [1 <<< 20, 16 <<< 20, 64 <<< 20] do
      # CSPRNG-fill so plaintext content matches the root Go bench
      # (crypto/rand). Not in the timing loop.
      plain = :crypto.strong_rand_bytes(size)
      run = fn -> pump(pipe, plain) end
      BenchUtil.bench_case("stream_pump", size, @min_iters, run)
    end

    :ok = ITB.free(pipe)
  end

  # Full incremental encrypt session over one buffer.
  defp pump(pipe, plain) do
    {:ok, session} = ITB.encrypt_stream(pipe)
    :ok = feed(session, plain)
    :ok = ITB.stream_end(session)
    :ok = drain(session)
    :ok = ITB.stream_free(session)
  end

  defp feed(_session, <<>>), do: :ok

  defp feed(session, data) do
    n = min(byte_size(data), @pump_buf)
    <<slice::binary-size(^n), rest::binary>> = data
    :ok = ITB.stream_write(session, slice)
    # A read before end never blocks; drain whatever the chain has
    # produced so far to bound the Go-side spool.
    :ok = drain_ready(session)
    feed(session, rest)
  end

  defp drain_ready(session) do
    case ITB.stream_read(session, @pump_buf) do
      {:ok, <<>>, _} -> :ok
      {:ok, _, true} -> :ok
      {:ok, _, false} -> drain_ready(session)
    end
  end

  defp drain(session) do
    case ITB.stream_read(session, @pump_buf) do
      {:ok, _, true} -> :ok
      {:ok, _, false} -> drain(session)
    end
  end
end

BenchStream.main()
