# temporary endpoint for testing
@app.post("/parse-test")
def test_parser(payload: dict):
    raw_log = payload.get("raw_log", "")
    parsed_result = parse_log(raw_log)

    if parsed_result:
        output_text = (
            f"timestamp: {parsed_result['timestamp']}\n"
            f"status: {parsed_result['status']}\n"
            f"pid: {parsed_result['pid']}\n"
            f"executable: {parsed_result['executable']}\n"
            f"operation: {parsed_result['operation']}\n"
            f"syscall: {parsed_result['syscall']}\n"
        )
        return Response(content=output_text, media_type="text/plain")
    else:
        return Response(
            content="Bu log satiri 'docker' kelimesi icermiyor veya gecersiz.\n",
            media_type="text/plain",
            status_code=400,
        )

