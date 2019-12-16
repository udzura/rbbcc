# FIXME: These should be class attributes?
$stars_max = 40
$log2_index_max = 65
$linear_index_max = 1025

module RbBCC
  # They're directly ported from table.py
  # They might be more looked like Ruby code
  module DisplayHelper
    def stars(val, val_max, width)
      i = 0
      text = ""
      while true
        break if (i > (width * val.to_f / val_max) - 1) || (i > width - 1)
        text += "*"
        i += 1
      end
      if val > val_max
        text = text[0...-1] + "+"
      end
      return text
    end

    def print_log2_hist(vals, val_type, strip_leading_zero)
      stars_max = $stars_max
      log2_dist_max = 64
      idx_max = -1
      val_max = 0

      vals.each_with_index do |v, i|
        idx_max = i if v > 0
        val_max = v if v > val_max
      end

      if idx_max <= 32
        header = "     %-19s : count     distribution"
        body = "%10d -> %-10d : %-8d |%-*s|"
        stars = stars_max
      else
        header = "               %-29s : count     distribution"
        body = "%20d -> %-20d : %-8d |%-*s|"
        stars = stars_max / 2
      end

      if idx_max > 0
        puts(header % val_type)
      end

      (1...(idx_max + 1)).each do |i|
        low = (1 << i) >> 1
        high = (1 << i) - 1
        if (low == high)
          low -= 1
        end
        val = vals[i]

        if strip_leading_zero
          if val
            puts(body % [low, high, val, stars,
                          stars(val, val_max, stars)])
            strip_leading_zero = false
          end
        else
          puts(body % [low, high, val, stars,
                        stars(val, val_max, stars)])
        end
      end
    end

    def print_linear_hist(vals, val_type)
      stars_max = $stars_max
      log2_dist_max = 64
      idx_max = -1
      val_max = 0

      vals.each_with_index do |v, i|
        idx_max = i if v > 0
        val_max = v if v > val_max
      end

      header = "     %-13s : count     distribution"
      body = "        %-10d : %-8d |%-*s|"
      stars = stars_max

      if idx_max >= 0
        puts(header % val_type);
      end

      (0...(idx_max + 1)).each do |i|
        val = vals[i]
        puts(body % [i, val, stars,
                     stars(val, val_max, stars)])
      end
    end
  end

  extend DisplayHelper
end
