import logging
from redis import StrictRedis

APP_ENV = "testing"

class BaseConfig:
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    #是否开启跟踪
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SECRET_KEY = "hello"
    '''
    根据业务和场景添加其他相关配置
    '''

    #配置Redis数据库
    REDIS_HOST = '127.0.0.1'
    REDIS_PORT = 6379
    REDIS_DB = 1
   # 配置session数据存储到redis数据库
    SESSION_TYPE = 'redis'
    # 指定存储session数据的redis的位置
    SESSION_REDIS = StrictRedis(host=REDIS_HOST, port=REDIS_PORT,db=REDIS_DB)
    # 开启session数据的签名，意思是让session数据不以明文形式存储
    SESSION_USE_SIGNER = True
    # 設置session的会话的超时时长 ：一天,全局指定
    PERMANENT_SESSION_LIFETIME = 3600 * 24


class TestingConfig(BaseConfig):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:124127@127.0.0.1:3306/test"

class DevelopmentConfig(BaseConfig):
    DEBUG = False
    LOGGING_LEVEL = logging.WARNING
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:124127@127.0.0.1:3306/test"

config = {
    "testing": TestingConfig,
    "devolopment": DevelopmentConfig,
}