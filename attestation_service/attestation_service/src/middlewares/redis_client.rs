use cache::client::RedisClient;

pub async fn get_redis_client() -> RedisClient {
    RedisClient::get_instance().unwrap()
}