package github.com/ChuChuuu/MyNet
/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stddef.h>

int AddFunction(int a , int b){
	return a+b;
}
int create_socket(){
	int fd;
	fd = socket(AF_INET,SOCK_DGRAM,0);
	return fd;
}
char* create_buffer(int buflen){
	char* buffer;
	buffer = malloc(buflen*sizeof(char));
	return buffer;
}

void printString(const char* s) {
    printf("%s", s);
}
*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	BUF_LEN = 1500
	INET_ADDRSTRLEN = 16
)

type MyConn struct {
	fd C.int
	Claddr C.struct_sockaddr_in
	Craddr C.struct_sockaddr_in
}
//no use
type MyUDPAddr struct{
	IP net.IP
	port int
}

func ListenUDP(network string,laddr *net.UDPAddr) (*MyConn,error){
	switch network {
	case "udp":
	default:
		return nil,errors.New("fail")
	}
	var address C.struct_sockaddr_in
	var status C.int
	address = udpaddrToCsock(laddr)
	FD := C.socket(syscall.AF_INET,syscall.SOCK_DGRAM,0)

	status = C.bind(FD,(*C.struct_sockaddr)(unsafe.Pointer(&address)),C.uint(unsafe.Sizeof(address)))
	if status == -1{
		err:=errors.New("fail to bind")
		return nil, err
	}
	conn := &MyConn{
		fd: FD,
		Claddr:address,
	}
	return conn,nil
}

//acts like ReadFromUDP in UDPConn but this structure is defined by us
func (conn *MyConn) ReadFromUDP(b []byte)(int,*net.UDPAddr,error){
	var addr C.struct_sockaddr_in
	var recv_length C.long
	len_address := C.uint(unsafe.Sizeof(addr))
	fmt.Printf("This is readfromudp\n")
	//create memory space
	var buffer string
	buffer_ptr := C.CString(buffer)
	defer C.free(unsafe.Pointer(buffer_ptr))
	//recv_length = C.recvfrom(conn.fd,unsafe.Pointer(buffer_ptr),BUF_LEN,0,(*C.struct_sockaddr)(unsafe.Pointer(&addr)),&len_address)
	recv_length = C.recvfrom(conn.fd,unsafe.Pointer(&b[0]),BUF_LEN,0,(*C.struct_sockaddr)(unsafe.Pointer(&addr)),&len_address)
	//deal with err (get-1)
	if int(recv_length) == -1{
		err:=errors.New("fail to receive")
		return -1, nil, err
	}
	/*
	//get the remote address and put it into UDPAddr
	r_port := myHtons(int(C.int(addr.sin_port)))//need myHtons to get correct remote port
	C.inet_ntop(syscall.AF_INET,unsafe.Pointer(&addr.sin_addr),buffer_ptr,INET_ADDRSTRLEN)
	r_ip := net.ParseIP(C.GoString(buffer_ptr))
	raddr := &net.UDPAddr{
		IP: r_ip,
		Port:int(r_port),
	}
	*/
	raddr := csockToUdpaddr(addr)
	return int(recv_length), raddr, nil
}

//acts like WriteToUDP in UDPConn but this structure is defined by us
//memory to send->use getCptrOfByteData or use &b[0] directly
func (conn *MyConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	var raddress C.struct_sockaddr_in
	//var buffer_ptr *C.char
	var success_send_length C.long
	//get information from UDPAddr and set the data of sockaddr_in
	raddress = udpaddrToCsock(addr)

	//how to set
	success_send_length = C.sendto(conn.fd, unsafe.Pointer(&b[0]), C.ulong(len(b)), 0, (*C.struct_sockaddr)(unsafe.Pointer(&raddress)),C.uint(unsafe.Sizeof(raddress)))
	if success_send_length == -1{
		err := errors.New("fail to send")
		return 0, err
	}
	return int(success_send_length),nil
}
// LocalAddr returns the local network address.
// this method of the sturcture that defined by us will return UDPAdrr
func (conn *MyConn)LocalAddr() (laddr net.Addr){
	//get the local address and put it into UDPAddr
	laddr = csockToUdpaddr(conn.Claddr)
	return
}
// Close closes the connection.
func (conn *MyConn)Close() error{
	var status C.int
	status = C.close(conn.fd)
	if status == -1{
		err :=errors.New("fail to close")
		return err
	}
	return nil
}
//like Htons in C
func myHtons(port int) uint16{
	//method1 14.799us
	var port_t uint16
	buf := new(bytes.Buffer)
	binary.Write(buf,binary.LittleEndian,uint16(port))
	binary.Read(buf,binary.BigEndian,&port_t)
	return port_t
}
//get the b[0] pointer of byte slice
func getCPtrOfByteData(b []byte) *C.char{
	shdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	ptr := (*C.char)(unsafe.Pointer(shdr.Data))
	//runtime alive?
	return ptr
}
//get information from UDPAddr and set the data of sockaddr_in
func udpaddrToCsock(addr *net.UDPAddr) (address C.struct_sockaddr_in){
	ip := addr.IP.String()
	if ip =="0.0.0.0"{
		ip = "0"
	}
	Cip := C.CString(ip)
	defer C.free(unsafe.Pointer(Cip))
	port := addr.Port
	address.sin_family = syscall.AF_INET
	address.sin_addr.s_addr = C.inet_addr(Cip)//need to free???
	address.sin_port = C.ushort(myHtons(port))
	return
}
//get the remote address and put it into UDPAddr
func csockToUdpaddr(address C.struct_sockaddr_in) (addr *net.UDPAddr){
	var buffer string
	buffer_ptr := C.CString(buffer)
	defer C.free(unsafe.Pointer(buffer_ptr))
	r_port := myHtons(int(C.int(address.sin_port)))//need myHtons to get correct remote port
	C.inet_ntop(syscall.AF_INET,unsafe.Pointer(&address.sin_addr),buffer_ptr,INET_ADDRSTRLEN)
	r_ip := net.ParseIP(C.GoString(buffer_ptr))
	addr = &net.UDPAddr{
		IP: r_ip,
		Port:int(r_port),
	}
	return
}
