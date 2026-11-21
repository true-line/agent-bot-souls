require 'socket'

abort 'requires macOS' unless RUBY_PLATFORM.include?('darwin')

case ARGV.shift
when 'probe'
  exit 1 unless ARGV.empty?
  left, right = UNIXSocket.pair
  exit(left.getpeereid.first == Process.euid && right.getpeereid.first == Process.euid)
when 'peer'
  exit 1 unless ARGV.length.between?(1, 2) && ARGV.all? { |uid| /\A[0-9]+\z/.match?(uid) }
  socket = UNIXSocket.for_fd(3)
  exit 1 unless socket.local_address.unix? && socket.remote_address.unix? &&
                socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM
  uid = socket.getpeereid.first
  exit 1 unless ARGV.map { |value| Integer(value, 10) }.include?(uid)
  puts uid
else
  exit 1
end
