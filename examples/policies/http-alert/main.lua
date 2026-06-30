function on_http_request_headers(event)
  local method = event.kind.method or "UNKNOWN"
  local target = event.kind.target or "/"
  return probe.emit_alert("HTTP request " .. method .. " " .. target)
end
