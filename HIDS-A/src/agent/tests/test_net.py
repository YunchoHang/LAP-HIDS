from agent.net import TcpFailoverClient

def test_client_targets_order_saved():
    c = TcpFailoverClient([("a",1),("b",2)])
    assert c.targets[0] == ("a",1)
