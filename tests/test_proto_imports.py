def test_relative_imports():
    import infraspectre.proto.messaging_schema_pb2 as pb2
    import infraspectre.proto.messaging_schema_pb2_grpc as pbrpc
    assert hasattr(pb2, "__file__")
    assert hasattr(pbrpc, "__file__")
