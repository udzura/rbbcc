module RbBCC
  module CPUHelper
    module_function
    def get_online_cpus
      return _read_cpu_range('/sys/devices/system/cpu/online')
    end

    def get_possible_cpus
      return _read_cpu_range('/sys/devices/system/cpu/possible')
    end

    # formatted like: '0,2-4,7-10'
    def _read_cpu_range(path)
      cpus = nil
      File.open(path, 'r') do |f|
        tmp = f.read.split(',').map do |range|
          if range.include?('-')
            start, end_ = *range.split('-')
            (start.to_i..end_.to_i).to_a
          else
            range.to_i
          end
        end
        cpus = tmp.flatten
      end
      cpus
    end
  end
end
