if echo > /dev/tcp/8.8.8.8/443 2>/dev/null; then
  echo "TCP connection successful!"
else
  echo "TCP connection failed!"
fi
