#include <mutex>
#include <condition_variable>


class WaitGroup {
public:
    WaitGroup() : count_(0) {}

    void add(int n) {
        std::unique_lock<std::mutex> lock(mutex_);
        count_ += n;
    }

    void done() {
        std::unique_lock<std::mutex> lock(mutex_);
        count_--;
        cv_.notify_one();
    }

    int size() {
        std::unique_lock<std::mutex> lock(mutex_);
        return count_;
    }

    void wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (count_ > 0) {
            cv_.wait(lock);
        }
    }

private:
    int count_;
    std::mutex mutex_;
    std::condition_variable cv_;
};