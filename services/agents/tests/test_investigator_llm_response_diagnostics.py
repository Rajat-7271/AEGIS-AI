from langchain_core.messages import AIMessage

from app.investigator.state import InvestigatorState, llm_response_diagnostics


def test_llm_response_diagnostics_capture_empty_response_without_raw_metadata():
    response = AIMessage(
        content="",
        response_metadata={
            "finish_reason": "length",
            "model_name": "openrouter/free",
            "headers": {
                "x-litellm-model-name": "provider/model-id",
                "x-litellm-call-id": "call-123",
                "authorization": "must-not-be-recorded",
            },
            "token_usage": {"prompt_tokens": 100, "completion_tokens": 2048},
        },
        usage_metadata={"input_tokens": 100, "output_tokens": 2048, "total_tokens": 2148},
        additional_kwargs={"reasoning": "must-not-be-recorded"},
    )

    diagnostics = llm_response_diagnostics(response)

    assert diagnostics["content_empty"] is True
    assert diagnostics["content_length"] == 0
    assert diagnostics["finish_reason"] == "length"
    assert diagnostics["resolved_model"] == "provider/model-id"
    assert diagnostics["provider_call_id"] == "call-123"
    assert diagnostics["token_usage"]["completion_tokens"] == 2048
    assert "authorization" not in str(diagnostics)
    assert "must-not-be-recorded" not in str(diagnostics)


def test_llm_response_diagnostics_are_persisted_in_audit_metadata():
    response = AIMessage(
        content="",
        response_metadata={"finish_reason": "stop"},
    )
    state = InvestigatorState(case_id="case-test")
    diagnostics = llm_response_diagnostics(response)

    state.log_llm_response(
        agent="ReconAgent",
        response="",
        diagnostics=diagnostics,
    )

    entry = state.audit_log[-1]
    assert entry.metadata["diagnostics"]["content_empty"] is True
    assert entry.metadata["diagnostics"]["finish_reason"] == "stop"
