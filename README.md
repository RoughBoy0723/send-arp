mac을 알아내는 패킷 3번 이상 보내기

공격이 끝나고 sender의 맥테이블을 정상적인 테이블로 원복 시켜주기

sender의 패킷을 받아 내 맥주소로 변환하여 target에게 전송

1. 센더가 arp리퀘스트를 브로드캐스트로 보내 타겟이 sender에게 보내는 리플라이 패킷을 뺏어서 내가 다시 보내주기

2. target이 보내는 arp 리퀘스트나 arp를 감지하면 -> 브로드 캐스트니까 보내야함

3. arp 패킷을 나한테 물어보는데 나는 그때 답해주면됨


mmap으로 아이피끼리 짝짓기


센더를 감염상태로 만들어 놓는것
