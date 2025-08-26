def test_relative_imports():
    import InfraSpectre.proto_stubs.messaging_schema_pb2 as pb2
    import InfraSpectre.proto_stubs.messaging_schema_pb2_grpc as pbrpc
    assert hasattr(pb2, "__file__")
    assert hasattr(pbrpc, "__file__")
