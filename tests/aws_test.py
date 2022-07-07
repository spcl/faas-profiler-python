#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for AWS specific logic.
"""

import pytest

from tests.aws_helper import get_aws_context_payload, get_aws_event_payload

from faas_profiler_python.aws import AWSContext, AWSEvent, EventTypes


def test_gateway_proxy_type_resolve():
    event = AWSEvent(get_aws_event_payload("apigateway-aws-proxy"))
    assert event.type == EventTypes.API_GATEWAY_AWS_PROXY


def test_gateway_authorizer_type_resolve():
    event = AWSEvent(get_aws_event_payload("apigateway-authorizer"))
    assert event.type == EventTypes.API_GATEWAY_AUTHORIZER


def test_sqs_type_resolve():
    event = AWSEvent(get_aws_event_payload("sqs-receive-message"))
    assert event.type == EventTypes.SQS


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("cloudfront-ab-test"),
    get_aws_event_payload("cloudfront-modify-querystring"),
    get_aws_event_payload("cloudfront-multiple-remote-calls-aggregate-response"),
    get_aws_event_payload("cloudfront-modify-response-header"),
    get_aws_event_payload("cloudfront-serve-object-on-viewer-device"),
    get_aws_event_payload("cloudfront-http-redirect"),
    get_aws_event_payload("cloudfront-redirect-unauthenticated-users"),
    get_aws_event_payload("cloudfront-normalize-querystring-to-improve-cache-hit"),
    get_aws_event_payload("cloudfront-access-request-in-response"),
    get_aws_event_payload("cloudfront-simple-remote-call"),
    get_aws_event_payload("cloudfront-redirect-on-viewer-country"),
    get_aws_event_payload("cloudfront-response-generation")
])
def test_cloudfront_event_type_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.CLOUDFRONT


def test_cloudwatch_logs_type_resolve():
    event = AWSEvent(get_aws_event_payload("cloudwatch-logs"))
    assert event.type == EventTypes.CLOUDWATCH_LOGS


def test_cloudwatch_scheduled_event_type_resolve():
    event = AWSEvent(get_aws_event_payload("cloudwatch-scheduled-event"))
    assert event.type == EventTypes.CLOUDWATCH_SCHEDULED_EVENT


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("dynamodb-update-json"),
    get_aws_event_payload("dynamodb-update"),
])
def test_dynamodb_event_type_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.DYNAMO_DB


def test_cloudformation_type_resolve():
    event = AWSEvent(get_aws_event_payload("cloudformation-create-request"))
    assert event.type == EventTypes.CLOUD_FORMATION


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("s3-delete"),
    get_aws_event_payload("s3-put"),
])
def test_s3_type_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.S3


def test_ses_type_resolve():
    event = AWSEvent(get_aws_event_payload("ses-email-receiving"))
    assert event.type == EventTypes.SES


def test_sns_type_resolve():
    event = AWSEvent(get_aws_event_payload("sns-notification"))
    assert event.type == EventTypes.SNS


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("config-item-change-notification"),
    get_aws_event_payload("config-oversized-item-change-notification"),
    get_aws_event_payload("config-periodic-rule")
])
def test_config_type_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.AWS_CONFIG


def test_code_commit_type_resolve():
    event = AWSEvent(get_aws_event_payload("codecommit-repository"))
    assert event.type == EventTypes.CODE_COMMIT


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("kinesis-analytics"),
    get_aws_event_payload("kinesis-analytics-compressed"),
    get_aws_event_payload("kinesis-analytics-kpl"),
    get_aws_event_payload("kinesis-analytics-dynamodb")
])
def test_kinesis_analytics_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.KINESIS_ANALYTICS


@pytest.mark.parametrize("event_payload", [
    get_aws_event_payload("kinesis-kinesis-firehose"),
    get_aws_event_payload("kinesis-apachelog"),
    get_aws_event_payload("kinesis-cloudwatch-logs-processor"),
    get_aws_event_payload("kinesis-streams-as-source"),
    get_aws_event_payload("kinesis-syslog"),
])
def test_kinesis_firehose_resolve(event_payload):
    event = AWSEvent(event_payload)
    assert event.type == EventTypes.KINESIS_FIREHOSE


def test_kinesis_stream_resolve():
    event = AWSEvent(get_aws_event_payload("kinesis-get-records"))
    assert event.type == EventTypes.KINESIS_STREAM


@pytest.mark.parametrize(
    "context_payload, expected_profile_id, expected_root_id, expected_span_id", [
        (get_aws_context_payload(custom=None), None, None, None),
        (get_aws_context_payload(custom={}), None, None, None),
        (get_aws_context_payload(custom={"_faas_profiler_context": {}}), None, None, None),
        (get_aws_context_payload(custom={"_faas_profiler_context": {
            "FaaS-Profiler-Profile-ID": 123
        }}), 123, None, None),
        (get_aws_context_payload(custom={"_faas_profiler_context": {
            "FaaS-Profiler-Profile-ID": 123,
            "FaaS-Profiler-Root-ID": 456
        }}), 123, 456, None),
        (get_aws_context_payload(custom={"_faas_profiler_context": {
            "FaaS-Profiler-Profile-ID": 123,
            "FaaS-Profiler-Root-ID": 456,
            "FaaS-Profiler-Span-ID": 789
        }}), 123, 456, 789),
    ])
def test_extract_tracing_from_context(
    context_payload,
    expected_profile_id,
    expected_root_id,
    expected_span_id
):
    context = AWSContext(context_payload)
    trace_ctx = context.extract_trace_context()

    assert trace_ctx.profile_id == expected_profile_id
    assert trace_ctx.root_id == expected_root_id
    assert trace_ctx.span_id == expected_span_id
